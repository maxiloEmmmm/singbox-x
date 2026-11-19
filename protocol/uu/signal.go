package uu

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
)

const signalLimit = 2 << 20

// signal owns the Engine.IO v4 websocket and its peer routing metadata.
type signal struct {
	// ws carries cloud control requests, SDP and trickled ICE candidates.
	ws *websocket.Conn
	// pending holds cloud events received before the control acknowledgement.
	pending [][]json.RawMessage
	// heartbeat is the server's negotiated silence allowance for a publisher.
	heartbeat time.Duration
	// readTimeout enables publisher reconnect when the socket goes silent.
	readTimeout time.Duration
}

// iceService is an ICE endpoint from the cloud control acknowledgement.
type iceService struct {
	// URLs holds either a string or an array, as returned by the cloud.
	URLs json.RawMessage `json:"urls"`
	// Username authenticates TURN.
	Username string `json:"username"`
	// Credential is the temporary TURN password.
	Credential string `json:"credential"`
}

// controlAck is the route and ICE policy assigned to one authenticated port-map session.
type controlAck struct {
	// ClientID is the remote client's signaling route.
	ClientID string `json:"client_id"`
	// IceID is the cloud-assigned ICE key, even when the offerer has its own.
	IceID string `json:"ice_id"`
	// AppID correlates the outbound control request.
	AppID string `json:"app_control_id"`
	// Services are the STUN and TURN endpoints for this session.
	Services []iceService `json:"iceServers"`
	// RelayOnly forbids direct ICE candidates when requested by the cloud.
	RelayOnly bool `json:"force_relay"`
}

// openSignal tries the room's WSS endpoints, e.g. a failed first origin -> the next origin.
func openSignal(ctx context.Context, httpClient *http.Client, room room) (*signal, error) {
	timeout := 8 * time.Second
	if room.TimeoutMS > 0 && room.TimeoutMS < 12000 {
		timeout = time.Duration(room.TimeoutMS) * time.Millisecond
	}
	for _, origin := range room.Signaling {
		endpoint, err := url.Parse(origin)
		if err != nil || endpoint.Scheme != "wss" || endpoint.Host == "" || endpoint.User != nil {
			continue
		}
		endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/socket.io/"
		endpoint.RawPath = ""
		endpoint.RawQuery = "transport=websocket&EIO=4"
		dialCtx, cancel := context.WithTimeout(ctx, timeout)
		ws, reply, err := websocket.Dial(dialCtx, endpoint.String(), &websocket.DialOptions{
			HTTPClient: httpClient, HTTPHeader: http.Header{"X-Nrd-Auth": {room.Token}},
		})
		if err == nil {
			ws.SetReadLimit(signalLimit)
			client := &signal{ws: ws}
			err = client.handshake(dialCtx)
			cancel()
			if err == nil {
				return client, nil
			}
			ws.CloseNow()
		} else {
			cancel()
			if reply != nil && reply.Body != nil {
				reply.Body.Close()
			}
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.New("UU 信令连接失败")
}

// handshake opens the default namespace, e.g. Engine.IO 0 -> Socket.IO 40 -> ready.
func (s *signal) handshake(ctx context.Context) error {
	opened := false
	for {
		message, err := s.readFrame(ctx, websocket.MessageText)
		if err != nil {
			return err
		}
		switch {
		case message[0] == '0' && !opened && json.Valid(message[1:]):
			opened = true
			var limits struct {
				Interval int64 `json:"pingInterval"`
				Timeout  int64 `json:"pingTimeout"`
			}
			_ = json.Unmarshal(message[1:], &limits)
			s.heartbeat = 45 * time.Second
			if limits.Interval > 0 && limits.Timeout > 0 && limits.Interval <= 300000 && limits.Timeout <= 300000 {
				s.heartbeat = time.Duration(min(limits.Interval+limits.Timeout, 300000)) * time.Millisecond
			}
			if err = s.ws.Write(ctx, websocket.MessageText, []byte("40")); err != nil {
				return err
			}
		case opened && strings.HasPrefix(string(message), "40"):
			return nil
		default:
			return errors.New("UU 信令握手格式不正确")
		}
	}
}

// control sends the capture-type-9 request and reads its acknowledgement, e.g. device ID -> ICE route.
func (s *signal) control(ctx context.Context, deviceID, appID string) (controlAck, error) {
	const ackID = 11
	var result controlAck
	streamer, _ := json.Marshal(map[string]any{
		"control_id":        appID,
		"device_capability": map[string]any{"display_info": []any{}, "ice_id": "", "video_codec_capability": []any{}},
	})
	header, _ := json.Marshal([]any{"control", map[string]any{
		"app_control_id": appID, "app_data": map[string]any{"_placeholder": true, "num": 0},
		"streamer_data": string(streamer),
	}})
	prefix := "451-" + strconv.Itoa(ackID)
	if err := s.ws.Write(ctx, websocket.MessageText, append([]byte(prefix), header...)); err != nil {
		return result, errors.New("无法发送 UU 控制请求")
	}
	// Upstream's native tool uses the legacy Engine.IO binary prefix for the attachment.
	if err := s.ws.Write(ctx, websocket.MessageBinary, append([]byte{4}, connectOptions(deviceID)...)); err != nil {
		return result, errors.New("无法发送 UU 控制参数")
	}
	for {
		id, packet, err := s.packet(ctx)
		if err != nil {
			return result, err
		}
		if id == ackID {
			if len(packet) != 2 || rawString(packet[0]) != "success" || json.Unmarshal(packet[1], &result) != nil ||
				result.ClientID == "" || (result.AppID != "" && result.AppID != appID) {
				return result, errors.New("UU 控制请求未获确认")
			}
			return result, nil
		}
		if id == 0 {
			if len(s.pending) == 64 {
				return result, errors.New("UU 信令待处理事件过多")
			}
			s.pending = append(s.pending, packet)
		}
	}
}

// event receives the next cloud event, e.g. "soac" -> the remote SDP or candidate.
func (s *signal) event(ctx context.Context) ([]json.RawMessage, error) {
	if len(s.pending) > 0 {
		value := s.pending[0]
		s.pending = s.pending[1:]
		return value, nil
	}
	for {
		id, value, err := s.packet(ctx)
		if err != nil || id == 0 {
			return value, err
		}
	}
}

// readFrame responds to Engine.IO heartbeats while reading text or binary frames.
func (s *signal) readFrame(ctx context.Context, mode websocket.MessageType) ([]byte, error) {
	for {
		read := ctx
		cancel := func() {}
		if s.readTimeout > 0 {
			read, cancel = context.WithTimeout(ctx, s.readTimeout)
		}
		kind, data, err := s.ws.Read(read)
		cancel()
		if err != nil {
			return nil, errors.New("UU 信令已断开")
		}
		if kind == websocket.MessageText && len(data) > 0 {
			switch data[0] {
			case '2':
				// Engine.IO text ping uses the same suffix for its pong.
				data[0] = '3'
				if err = s.ws.Write(ctx, websocket.MessageText, data); err != nil {
					return nil, errors.New("UU 信令心跳失败")
				}
				continue
			case '1':
				return nil, errors.New("UU 云端关闭了信令房间")
			case '4':
				if string(data) == "41" {
					return nil, errors.New("UU 云端关闭了信令房间")
				}
			}
		}
		if kind == mode && len(data) > 0 {
			return data, nil
		}
	}
}

// packet decodes a Socket.IO event or ack, e.g. "4311[...]" -> ack 11.
func (s *signal) packet(ctx context.Context) (int, []json.RawMessage, error) {
	for {
		frame, err := s.readFrame(ctx, websocket.MessageText)
		if err != nil {
			return 0, nil, err
		}
		if len(frame) < 2 || frame[0] != '4' || !strings.ContainsRune("2356", rune(frame[1])) {
			continue
		}
		jsonStart := strings.IndexByte(string(frame), '[')
		if jsonStart < 2 {
			return 0, nil, errors.New("UU 信令缺少事件内容")
		}
		kind := frame[1]
		ackStart, count := 2, 0
		if kind == '5' || kind == '6' {
			dash := strings.IndexByte(string(frame[:jsonStart]), '-')
			if dash < 3 {
				return 0, nil, errors.New("UU 信令附件头无效")
			}
			count, err = strconv.Atoi(string(frame[2:dash]))
			if err != nil || count < 1 || count > 8 {
				return 0, nil, errors.New("UU 信令附件数无效")
			}
			ackStart = dash + 1
		}
		id := 0
		if kind == '3' || kind == '6' {
			id, err = strconv.Atoi(string(frame[ackStart:jsonStart]))
			if err != nil || id < 1 {
				return 0, nil, errors.New("UU 信令确认编号无效")
			}
		}
		var value []json.RawMessage
		if json.Unmarshal(frame[jsonStart:], &value) != nil {
			return 0, nil, errors.New("UU 信令事件格式不正确")
		}
		if count != 0 {
			value, err = s.attachments(ctx, value, count)
		}
		return id, value, err
	}
}

// attachments resolves binary placeholders, e.g. compressed answer bytes -> gzip_sdp as base64.
func (s *signal) attachments(ctx context.Context, value []json.RawMessage, count int) ([]json.RawMessage, error) {
	data := make([]string, 0, count)
	for range count {
		raw, err := s.readFrame(ctx, websocket.MessageBinary)
		if err != nil {
			return nil, err
		}
		if len(raw) > 2 && raw[0] == 4 && raw[1] == 0x1f {
			raw = raw[1:]
		}
		data = append(data, base64.StdEncoding.EncodeToString(raw))
	}
	for i, part := range value {
		var decoded any
		if json.Unmarshal(part, &decoded) == nil {
			value[i], _ = json.Marshal(fillAttachment(decoded, data))
		}
	}
	// Port-map authorization is carried by the control attachment itself. Preserve it
	// even if this cloud version sends a header without a JSON placeholder.
	if len(value) == 2 && len(data) == 1 && rawString(value[0]) == "be-controlled" {
		attachment, _ := json.Marshal(data[0])
		value = append(value, attachment)
	}
	return value, nil
}

// fillAttachment replaces binary placeholders anywhere in an event object.
func fillAttachment(item any, attachments []string) any {
	switch node := item.(type) {
	case map[string]any:
		if node["_placeholder"] == true {
			if number, ok := node["num"].(float64); ok && number >= 0 && number < float64(len(attachments)) && float64(int(number)) == number {
				return attachments[int(number)]
			}
		}
		for key, child := range node {
			node[key] = fillAttachment(child, attachments)
		}
	case []any:
		for i, child := range node {
			node[i] = fillAttachment(child, attachments)
		}
	}
	return item
}

// soac sends SDP or ICE to the peer, e.g. "offer" -> a cloud-routed signaling event.
func (s *signal) soac(ctx context.Context, to string, body any) error {
	data, err := json.Marshal([]any{"soac", map[string]any{"client_id": to, "data": body}})
	if err != nil {
		return errors.New("无法编码 UU 信令")
	}
	if s.ws.Write(ctx, websocket.MessageText, append([]byte("42"), data...)) != nil {
		return errors.New("无法发送 UU 信令")
	}
	return nil
}

// rawString reads a JSON string and returns empty for another type, e.g. null -> "".
func rawString(raw json.RawMessage) string {
	var value string
	_ = json.Unmarshal(raw, &value)
	return value
}

// emit sends a publisher event, e.g. ack 11 with room_info requests the local room status.
func (s *signal) emit(ctx context.Context, ack int, event string, args ...any) error {
	body, err := json.Marshal(append([]any{event}, args...))
	if err != nil {
		return errors.New("无法编码 UU 被控端信令")
	}
	prefix := "42"
	if ack > 0 {
		prefix += strconv.Itoa(ack)
	}
	if s.ws.Write(ctx, websocket.MessageText, append([]byte(prefix), body...)) != nil {
		return errors.New("无法发送 UU 被控端信令")
	}
	return nil
}
