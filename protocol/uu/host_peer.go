package uu

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/webrtc/v4"
)

// hostPeer is one controller's WebRTC carrier, distinct from the singleton publisher.
type hostPeer struct {
	// ctx owns the carrier and all accepted TCP streams.
	ctx context.Context
	// cancel closes just this controller's peer and streams.
	cancel context.CancelFunc
	// connection applies trickle ICE from the publisher room.
	connection *webrtc.PeerConnection
	// route correlates messages with this controller.
	route route
}

// hostSOAC is a cloud-routed offer or trickle candidate.
type hostSOAC struct {
	// Type is offer or candidate.
	Type string `json:"type"`
	// Client is the controller route in unwrapped messages.
	Client string `json:"client_id"`
	// Ice is the room's session key.
	Ice json.RawMessage `json:"ice_id"`
	// App correlates the controller request with this offer.
	App string `json:"app_control_id"`
	// SDP is the plain offer.
	SDP string `json:"sdp"`
	// Gzip carries an alternative base64+gzip offer.
	Gzip string `json:"gzip_sdp"`
	// Candidate is a candidate string or structured Pion candidate.
	Candidate json.RawMessage `json:"candidate"`
	// Mid identifies the media section for a legacy string candidate.
	Mid *string `json:"sdp_mid"`
	// MLine indexes the media section for a legacy string candidate.
	MLine *uint16 `json:"sdp_mline_index"`
}

// handleHostSOAC dispatches an offer only after a cloud port-map announcement.
func (h *HostService) handleHostSOAC(ctx context.Context, s *signal, raw json.RawMessage, pending map[string]hostSetup, peers map[string]*hostPeer) {
	var envelope struct {
		Client string          `json:"client_id"`
		Data   json.RawMessage `json:"data"`
	}
	if json.Unmarshal(raw, &envelope) != nil {
		return
	}
	if len(envelope.Data) > 0 && string(envelope.Data) != "null" {
		raw = envelope.Data
	}
	var body hostSOAC
	if json.Unmarshal(raw, &body) != nil {
		return
	}
	id := strings.Trim(string(body.Ice), "\"")
	remote := envelope.Client
	if remote == "" {
		remote = body.Client
	}
	switch body.Type {
	case "candidate":
		if peer := peers[id]; peer != nil && (remote == "" || peer.route.client == remote) &&
			(body.App == "" || peer.route.app == body.App) {
			peer.addCandidate(body)
		}
	case "offer":
		if id == "" || id == "null" || remote == "" {
			return
		}
		key := id
		announcement, ok := pending[key]
		if !ok {
			key = ""
			announcement, ok = pending[key]
		}
		if !ok || time.Since(announcement.At) > time.Minute ||
			(announcement.Transport.ClientID != "" && announcement.Transport.ClientID != remote) ||
			(announcement.Transport.AppID != "" && body.App != "" && announcement.Transport.AppID != body.App) {
			return
		}
		delete(pending, key)
		if len(peers) >= 32 && peers[id] == nil {
			return
		}
		if body.App == "" {
			body.App = announcement.Transport.AppID
		}
		peer, err := h.answerHostOffer(ctx, s, route{client: remote, ice: id, app: body.App}, announcement.Transport, body)
		if err != nil {
			h.logger.Warn("UU incoming port map: ", err)
			return
		}
		if old := peers[id]; old != nil {
			old.cancel()
		}
		peers[id] = peer
	}
}

// answerHostOffer opens one WebRTC connection, e.g. a controller's SDP -> an answer and file channel.
func (h *HostService) answerHostOffer(signalingCtx context.Context, s *signal, route route, iceOptions controlAck, offer hostSOAC) (*hostPeer, error) {
	sdp, err := decodeAnswer(offer.SDP, offer.Gzip)
	if err != nil {
		return nil, errors.New("UU offer SDP 无效")
	}
	config, err := iceConfiguration(iceOptions)
	if err != nil {
		return nil, err
	}
	settings := webrtc.SettingEngine{}
	settings.SetNet(h.network)
	settings.SetInterfaceFilter(h.network.allowedInterface)
	settings.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	settings.SetSCTPMaxMessageSize(256 * 1024)
	if err = settings.SetAnsweringDTLSRole(webrtc.DTLSRoleServer); err != nil {
		return nil, errors.New("UU 无法设置应答端 DTLS 角色")
	}
	pc, err := webrtc.NewAPI(webrtc.WithSettingEngine(settings)).NewPeerConnection(config)
	if err != nil {
		return nil, errors.New("UU 无法创建接收端 WebRTC")
	}
	ctx, cancel := context.WithCancel(h.ctx)
	context.AfterFunc(ctx, func() { _ = pc.Close() })
	var controlUsed, fileUsed, notified atomic.Bool
	pc.OnDataChannel(func(channel *webrtc.DataChannel) {
		switch channel.Label() {
		case controlChannel:
			if controlUsed.CompareAndSwap(false, true) {
				bindHostControl(channel)
			}
		case fileChannel:
			if fileUsed.CompareAndSwap(false, true) {
				bindHostRelay(ctx, cancel, channel, h.port)
			}
		}
	})
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		switch state {
		case webrtc.PeerConnectionStateConnected:
			if notified.CompareAndSwap(false, true) && route.app != "" {
				go func() {
					send, done := context.WithTimeout(signalingCtx, 8*time.Second)
					defer done()
					_ = s.emit(send, 0, "ice_finished_log", map[string]string{
						"ice_id": route.ice, "app_control_id": route.app,
					})
				}()
			}
		case webrtc.PeerConnectionStateFailed, webrtc.PeerConnectionStateClosed:
			cancel()
		}
	})
	if pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: sdp}) != nil {
		cancel()
		return nil, errors.New("UU 无法应用接收端 offer")
	}
	candidates := make(chan webrtc.ICECandidateInit, 128)
	pc.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil {
			return
		}
		select {
		case candidates <- candidate.ToJSON():
		case <-ctx.Done():
		default:
			cancel()
		}
	})
	answer, err := pc.CreateAnswer(nil)
	if err != nil || pc.SetLocalDescription(answer) != nil {
		cancel()
		return nil, errors.New("UU 无法生成接收端 answer")
	}
	answerCtx, done := context.WithTimeout(signalingCtx, 8*time.Second)
	defer done()
	err = s.soac(answerCtx, route.client, map[string]any{
		"type": "answer", "sdp": answer.SDP,
		"ice_id": route.ice, "app_control_id": route.app, "client_id": route.client,
	})
	if err != nil {
		cancel()
		return nil, err
	}
	go sendCandidates(ctx, s, route, candidates)
	return &hostPeer{ctx: ctx, cancel: cancel, connection: pc, route: route}, nil
}

// addCandidate accepts legacy and structured candidates, e.g. an ICE JSON object -> Pion.
func (p *hostPeer) addCandidate(body hostSOAC) {
	candidate := webrtc.ICECandidateInit{Candidate: rawString(body.Candidate), SDPMid: body.Mid, SDPMLineIndex: body.MLine}
	if candidate.Candidate == "" {
		_ = json.Unmarshal(body.Candidate, &candidate)
	}
	if candidate.Candidate != "" {
		_ = p.connection.AddICECandidate(candidate)
	}
}

// bindHostControl replies to the tool's echo, e.g. request seq 1 -> readiness acknowledgement.
func bindHostControl(channel *webrtc.DataChannel) {
	var sequence atomic.Uint64
	channel.OnMessage(func(message webrtc.DataChannelMessage) {
		if message.IsString {
			return
		}
		action, ok := wireBytes(message.Data, 3)
		if !ok || wireNumber(action, 1) != 0 {
			return
		}
		args, _ := json.Marshal(map[string]uint64{"seq": wireNumber(message.Data, 1)})
		reply := appendBytes(appendNumber(nil, 1, 1), 2, args)
		reply = appendBytes(reply, 4, nil)
		body := appendNumber(nil, 1, sequence.Add(1))
		_ = channel.Send(appendBytes(body, 3, reply))
	})
}
