package uu

import (
	"context"
	"encoding/json"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/pion/webrtc/v4"
)

// flowKey distinguishes simultaneous flows inside one controller's carrier.
type flowKey struct {
	// session is the controller's session identifier.
	session uint64
	// rule is the selected mapping rule.
	rule uint64
	// stream identifies one TCP connection.
	stream uint64
}

// hostRelay bridges one incoming FILE channel to the configured local mixed listener.
type hostRelay struct {
	// ctx closes the relay and all TCP flows with the peer.
	ctx context.Context
	// sender enforces the bounded SCTP send window.
	sender *channelSender
	// port is the only permitted destination, always on IPv4 loopback.
	port uint16
	// mu serializes registration and removal of stream routes.
	mu sync.Mutex
	// flows contains live and dialing TCP flows on this carrier.
	flows map[flowKey]*mappedFlow
}

// bindHostRelay attaches TCP forwarding to the FILE channel, e.g. a map SYN -> dial mixed.
func bindHostRelay(ctx context.Context, cancel context.CancelFunc, channel *webrtc.DataChannel, port uint16) {
	relay := &hostRelay{
		ctx: ctx, sender: newChannelSender(cancel, channel), port: port, flows: make(map[flowKey]*mappedFlow),
	}
	channel.OnMessage(relay.receive)
}

// receive dispatches peer frames, e.g. DATA is queued for only its own TCP flow.
func (r *hostRelay) receive(message webrtc.DataChannelMessage) {
	if message.IsString || r.ctx.Err() != nil {
		return
	}
	frame, ok := decodeFrame(message.Data)
	if !ok {
		return
	}
	key := flowKey{frame.session, frame.rule, frame.stream}
	if frame.kind == wireSYN {
		r.open(key, frame.payload)
		return
	}
	if frame.kind != wireDATA && frame.kind != wireFIN {
		return
	}
	r.mu.Lock()
	flow := r.flows[key]
	r.mu.Unlock()
	if flow == nil {
		return
	}
	select {
	case flow.incoming <- frame:
	default:
		// A blocked local TCP flow must not hold the shared FILE channel.
		flow.cancel()
	}
}

// open validates a mapping, e.g. SYN 127.0.0.1:10808 -> one bounded local dial.
func (r *hostRelay) open(key flowKey, payload []byte) {
	var target struct {
		Version int    `json:"version"`
		Host    string `json:"target_host"`
		Port    uint16 `json:"target_port"`
	}
	if len(payload) > 4096 || json.Unmarshal(payload, &target) != nil ||
		target.Version != 1 || target.Host != "127.0.0.1" || target.Port != r.port {
		r.ack(key, false, "target not permitted")
		return
	}
	r.mu.Lock()
	if r.flows[key] != nil {
		r.mu.Unlock()
		return
	}
	if len(r.flows) >= maxFlows {
		r.mu.Unlock()
		r.ack(key, false, "too many streams")
		return
	}
	ctx, cancel := context.WithCancel(r.ctx)
	flow := &mappedFlow{cancel: cancel, incoming: make(chan mapFrame, receiveQueue)}
	r.flows[key] = flow
	r.mu.Unlock()
	go r.relay(ctx, key, flow)
}

// relay sends SYN_ACK after local connect, then carries data until either TCP or WebRTC ends.
func (r *hostRelay) relay(ctx context.Context, key flowKey, flow *mappedFlow) {
	defer func() {
		r.mu.Lock()
		delete(r.flows, key)
		r.mu.Unlock()
		flow.cancel()
	}()
	dial := net.Dialer{Timeout: 8 * time.Second}
	conn, err := dial.DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(r.port))))
	if err != nil {
		r.ack(key, false, "mixed listener unavailable")
		return
	}
	defer conn.Close()
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()
	if r.ack(key, true, "") != nil {
		return
	}
	defer r.sender.send(r.ctx, key.frame(wireFIN, nil))
	go writeMappedTCP(ctx, flow.cancel, conn, flow.incoming)
	buffer := make([]byte, streamChunk)
	for r.sender.waitWritable(ctx) == nil {
		count, err := conn.Read(buffer)
		if count > 0 && r.sender.send(ctx, key.frame(wireDATA, buffer[:count])) != nil {
			return
		}
		if err != nil {
			return
		}
	}
}

// ack returns the requested flow IDs with a local dial result, e.g. busy -> ok=false.
func (r *hostRelay) ack(key flowKey, ok bool, reason string) error {
	payload, _ := json.Marshal(struct {
		Version int    `json:"version"`
		OK      bool   `json:"ok"`
		Error   string `json:"error,omitempty"`
	}{1, ok, reason})
	return r.sender.send(r.ctx, key.frame(wireSYNACK, payload))
}

// frame forms an outgoing frame from the original flow key, e.g. FIN echoes all three IDs.
func (key flowKey) frame(kind uint64, payload []byte) mapFrame {
	return mapFrame{session: key.session, rule: key.rule, stream: key.stream, kind: kind, payload: payload}
}
