package uu

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/pion/ice/v4"
	"github.com/pion/webrtc/v4"
)

const (
	controlChannel = "CONTROL_DATA_CHANNEL"
	fileChannel    = "FILE_DATA_CHANNEL"
)

// route identifies one peer for all SDP and ICE messages.
type route struct {
	// client is the remote signaling address.
	client string
	// ice is the cloud-assigned session identifier.
	ice string
	// app is the controller's connection ID.
	app string
}

// openPortSession creates one shared carrier, e.g. 185 -> one FILE data channel.
func openPortSession(parent context.Context, cloud cloudClient, creds credentials, deviceID string, network *physicalNet) (*portSession, error) {
	connect, stop := context.WithTimeout(parent, 35*time.Second)
	defer stop()
	room, err := cloud.join(connect, creds, deviceID)
	if err != nil {
		return nil, err
	}
	signal, err := openSignal(connect, cloud.http, room)
	if err != nil {
		return nil, err
	}
	sessionCtx, cancel := context.WithCancel(parent)
	context.AfterFunc(sessionCtx, func() { _ = signal.ws.CloseNow() })
	success := false
	defer func() {
		if !success {
			cancel()
		}
	}()
	app, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}
	ack, err := signal.control(connect, creds.DeviceID, app.String())
	if err != nil {
		return nil, err
	}
	if ack.IceID == "" {
		var random [16]byte
		if _, err = rand.Read(random[:]); err != nil {
			return nil, err
		}
		ack.IceID = hex.EncodeToString(random[:])
	}
	routing := route{client: ack.ClientID, ice: ack.IceID, app: app.String()}
	config, err := iceConfiguration(ack)
	if err != nil {
		return nil, err
	}
	settings := webrtc.SettingEngine{}
	settings.SetNet(network)
	settings.SetInterfaceFilter(network.allowedInterface)
	settings.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	settings.SetSCTPMaxMessageSize(256 * 1024)
	peer, err := webrtc.NewAPI(webrtc.WithSettingEngine(settings)).NewPeerConnection(config)
	if err != nil {
		return nil, errors.New("无法建立 UU WebRTC 连接")
	}
	context.AfterFunc(sessionCtx, func() { _ = peer.Close() })
	peer.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateClosed {
			cancel()
		}
	})
	control, err := peer.CreateDataChannel(controlChannel, nil)
	if err != nil {
		return nil, errors.New("无法创建 UU CONTROL 通道")
	}
	file, err := peer.CreateDataChannel(fileChannel, nil)
	if err != nil {
		return nil, errors.New("无法创建 UU 端口映射通道")
	}
	var random [8]byte
	if _, err = rand.Read(random[:]); err != nil {
		return nil, err
	}
	mapping := newPortSession(sessionCtx, cancel, binary.BigEndian.Uint64(random[:])|1, file)
	echoReady := bindEcho(control, cancel)
	fileReady := make(chan struct{})
	file.OnOpen(func() { close(fileReady) })

	localCandidates := make(chan webrtc.ICECandidateInit, 128)
	peer.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate != nil {
			select {
			case localCandidates <- candidate.ToJSON():
			case <-sessionCtx.Done():
			default:
				cancel()
			}
		}
	})
	offer, err := peer.CreateOffer(nil)
	if err != nil || peer.SetLocalDescription(offer) != nil {
		return nil, errors.New("无法生成 UU WebRTC offer")
	}
	sdp := offer.SDP
	if index := strings.Index(sdp, "a=group:BUNDLE"); index >= 0 {
		// Preserve the upstream viewer's capability marker only in the transmitted SDP.
		sdp = sdp[:index] + "a=x-uuremote-quic\r\n" + sdp[index:]
	}
	request := map[string]any{"type": "offer", "sdp": sdp, "ice_id": routing.ice, "app_control_id": routing.app, "ice_network_type": 3}
	if err = signal.soac(connect, routing.client, request); err != nil {
		return nil, err
	}

	remoteDone := make(chan error, 1)
	go func() { remoteDone <- readPeerSignals(sessionCtx, signal, peer, routing) }()
	go sendCandidates(sessionCtx, signal, routing, localCandidates)
	for fileReady != nil || echoReady != nil {
		select {
		case <-fileReady:
			fileReady = nil
		case <-echoReady:
			echoReady = nil
		case err = <-remoteDone:
			return nil, err
		case <-sessionCtx.Done():
			return nil, errors.New("UU 端口映射通道已断开")
		case <-connect.Done():
			return nil, errors.New("UU 端口映射握手超时")
		}
	}
	go func() {
		select {
		case <-sessionCtx.Done():
		case err := <-remoteDone:
			// If signaling drops after ICE comes up, existing TCP flows can still use SCTP.
			// An explicit cloud release does terminate this peer.
			if errors.Is(err, errPeerReleased) {
				cancel()
			}
		}
	}()
	success = true
	return mapping, nil
}

// bindEcho implements the tool readiness handshake, e.g. action 1 seq=1 -> ready.
func bindEcho(channel *webrtc.DataChannel, cancel context.CancelFunc) <-chan struct{} {
	ready := make(chan struct{}, 1)
	channel.OnOpen(func() {
		flags := []byte{8, 6, 16, 2, 24, 1, 32, 2, 48, 2, 56, 2, 72, 1}
		action := appendBytes(appendNumber(nil, 1, 0), 4, flags)
		if channel.Send(appendBytes(appendNumber(nil, 1, 1), 3, action)) != nil {
			cancel()
		}
	})
	channel.OnClose(cancel)
	channel.OnMessage(func(message webrtc.DataChannelMessage) {
		if message.IsString {
			return
		}
		action, ok := wireBytes(message.Data, 3)
		if !ok {
			return
		}
		switch wireNumber(action, 1) {
		case 0:
			seq := wireNumber(message.Data, 1)
			args, _ := json.Marshal(map[string]uint64{"seq": seq})
			reply := appendBytes(appendNumber(nil, 1, 1), 2, args)
			reply = appendBytes(reply, 4, nil)
			_ = channel.Send(appendBytes(appendNumber(nil, 1, 2), 3, reply))
		case 1:
			var ack struct {
				Sequence uint64 `json:"seq"`
			}
			args, _ := wireBytes(action, 2)
			if json.Unmarshal(args, &ack) == nil && ack.Sequence == 1 {
				select {
				case ready <- struct{}{}:
				default:
				}
			}
		}
	})
	return ready
}

// iceConfiguration converts signed cloud ICE metadata, e.g. force_relay -> TURN-only.
func iceConfiguration(ack controlAck) (webrtc.Configuration, error) {
	var config webrtc.Configuration
	hasTURN := false
	for _, service := range ack.Services {
		var endpoints []string
		if json.Unmarshal(service.URLs, &endpoints) != nil {
			if one := rawString(service.URLs); one != "" {
				endpoints = []string{one}
			}
		}
		if len(endpoints) == 0 {
			return config, errors.New("UU ICE 服务地址无效")
		}
		for _, url := range endpoints {
			scheme, _, _ := strings.Cut(url, ":")
			switch strings.ToLower(scheme) {
			case "turn", "turns":
				hasTURN = true
			case "stun", "stuns":
			default:
				return config, errors.New("UU ICE 服务地址无效")
			}
		}
		config.ICEServers = append(config.ICEServers, webrtc.ICEServer{
			URLs: endpoints, Username: service.Username, Credential: service.Credential,
			CredentialType: webrtc.ICECredentialTypePassword,
		})
	}
	if ack.RelayOnly {
		if !hasTURN {
			return config, errors.New("UU 要求中继但未返回 TURN 服务")
		}
		config.ICETransportPolicy = webrtc.ICETransportPolicyRelay
	}
	return config, nil
}

// sendCandidates sends local ICE updates after the offer, e.g. UDP candidate -> cloud SOAC.
func sendCandidates(ctx context.Context, signal *signal, route route, candidates <-chan webrtc.ICECandidateInit) {
	for {
		select {
		case <-ctx.Done():
			return
		case candidate := <-candidates:
			if candidate.SDPMid == nil || *candidate.SDPMid == "" {
				mid := "0"
				candidate.SDPMid = &mid
			}
			if candidate.SDPMLineIndex == nil {
				line := uint16(0)
				candidate.SDPMLineIndex = &line
			}
			event := map[string]any{"type": "candidate", "candidate": candidate, "ice_id": route.ice, "app_control_id": route.app}
			write, cancel := context.WithTimeout(ctx, 8*time.Second)
			err := signal.soac(write, route.client, event)
			cancel()
			if err != nil {
				return
			}
		}
	}
}

var errPeerReleased = errors.New("UU 对端关闭了端口映射")

// readPeerSignals applies answer and ICE updates, e.g. early ICE -> queue until SDP arrives.
func readPeerSignals(ctx context.Context, signal *signal, peer *webrtc.PeerConnection, route route) error {
	var early []webrtc.ICECandidateInit
	answered := false
	for {
		packet, err := signal.event(ctx)
		if err != nil {
			return err
		}
		if len(packet) < 2 {
			continue
		}
		name := rawString(packet[0])
		var outer struct {
			Client string          `json:"client_id"`
			Data   json.RawMessage `json:"data"`
		}
		raw := packet[1]
		if json.Unmarshal(raw, &outer) == nil && len(outer.Data) > 0 && string(outer.Data) != "null" {
			raw = outer.Data
		}
		var body struct {
			Type      string          `json:"type"`
			Ice       json.RawMessage `json:"ice_id"`
			App       string          `json:"app_control_id"`
			SDP       string          `json:"sdp"`
			Gzip      string          `json:"gzip_sdp"`
			Candidate json.RawMessage `json:"candidate"`
			Mid       *string         `json:"sdp_mid"`
			MLine     *uint16         `json:"sdp_mline_index"`
		}
		if json.Unmarshal(raw, &body) != nil || (outer.Client != "" && outer.Client != route.client) ||
			(len(body.Ice) > 0 && strings.Trim(string(body.Ice), "\"") != route.ice) || (body.App != "" && body.App != route.app) {
			continue
		}
		if name == "released" || name == "left" || name == "leave" {
			return errPeerReleased
		}
		if name != "soac" {
			continue
		}
		switch body.Type {
		case "answer":
			if answered {
				continue
			}
			sdp, err := decodeAnswer(body.SDP, body.Gzip)
			if err != nil || peer.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: sdp}) != nil {
				return errors.New("UU WebRTC answer 无效")
			}
			answered = true
			for _, candidate := range early {
				_ = peer.AddICECandidate(candidate)
			}
			early = nil
		case "candidate":
			candidate := webrtc.ICECandidateInit{Candidate: rawString(body.Candidate), SDPMid: body.Mid, SDPMLineIndex: body.MLine}
			if candidate.Candidate == "" {
				_ = json.Unmarshal(body.Candidate, &candidate)
			}
			if candidate.Candidate == "" {
				continue
			}
			if answered {
				_ = peer.AddICECandidate(candidate)
			} else if len(early) < 128 {
				early = append(early, candidate)
			}
		}
	}
}

// decodeAnswer handles both text and upstream gzip SDP, e.g. base64+gzip -> SDP string.
func decodeAnswer(text, compressed string) (string, error) {
	const max = 1 << 20
	if text != "" && len(text) <= max {
		return text, nil
	}
	data, err := base64.StdEncoding.DecodeString(compressed)
	if err != nil || len(data) == 0 || len(data) > max {
		return "", errors.New("UU SDP 压缩内容无效")
	}
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	defer reader.Close()
	raw, err := io.ReadAll(io.LimitReader(reader, max+1))
	if err != nil || len(raw) == 0 || len(raw) > max {
		return "", errors.New("UU SDP 大小无效")
	}
	return string(raw), nil
}
