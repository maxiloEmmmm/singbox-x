package uu

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/webrtc/v4"
)

const (
	streamChunk  = 16 * 1024
	maxFlows     = 256
	receiveQueue = 16
	sendHigh     = 512 * 1024
	sendLow      = sendHigh - streamChunk
)

// mappedFlow stores the incoming queue for one accepted local TCP connection.
type mappedFlow struct {
	// cancel stops the associated TCP streams under closure or overflow.
	cancel context.CancelFunc
	// incoming contains ordered messages owned by this flow, including FIN.
	incoming chan mapFrame
}

// portSession multiplexes loopback TCP flows over one UU FILE data channel.
type portSession struct {
	// ctx ends the connection and all mapped flows.
	ctx context.Context
	// channelSender limits the shared SCTP send queue in both roles.
	*channelSender
	// id identifies this mapping session.
	id uint64
	// next assigns monotonically increasing non-reused stream IDs.
	next atomic.Uint64
	// flowMu protects the map of live streams.
	flowMu sync.Mutex
	// flows maps remote frame stream IDs to their local TCP writer.
	flows map[uint64]*mappedFlow
}

// channelSender manages writes and backpressure for one UU FILE data channel.
type channelSender struct {
	// cancel closes the peer if the channel fails.
	cancel context.CancelFunc
	// channel carries port-map messages.
	channel *webrtc.DataChannel
	// sendMu serializes SCTP sends with the buffer threshold check.
	sendMu sync.Mutex
	// window is closed and replaced when the SCTP send buffer drains.
	window chan struct{}
}

// newPortSession initializes a FILE data channel, e.g. one peer -> many flows.
func newPortSession(ctx context.Context, cancel context.CancelFunc, id uint64, channel *webrtc.DataChannel) *portSession {
	session := &portSession{
		ctx: ctx, channelSender: newChannelSender(cancel, channel), id: id,
		flows: make(map[uint64]*mappedFlow),
	}
	channel.OnMessage(session.receive)
	return session
}

// newChannelSender binds the common FILE lifecycle, e.g. channel close cancels the peer.
func newChannelSender(cancel context.CancelFunc, channel *webrtc.DataChannel) *channelSender {
	sender := &channelSender{cancel: cancel, channel: channel, window: make(chan struct{})}
	channel.SetBufferedAmountLowThreshold(sendLow)
	channel.OnBufferedAmountLow(sender.wakeSenders)
	channel.OnClose(cancel)
	return sender
}

// wakeSenders broadcasts a writable transition, e.g. buffer falls below sendLow.
func (p *channelSender) wakeSenders() {
	p.sendMu.Lock()
	close(p.window)
	p.window = make(chan struct{})
	p.sendMu.Unlock()
}

// waitWritable enforces backpressure before TCP read, e.g. full SCTP -> wait.
func (p *channelSender) waitWritable(ctx context.Context) error {
	for {
		p.sendMu.Lock()
		available := p.channel.BufferedAmount() <= sendLow
		waiter := p.window
		p.sendMu.Unlock()
		if available {
			return ctx.Err()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-waiter:
		}
	}
}

// send emits one UU frame, e.g. DATA on flow 7 -> the shared SCTP channel.
func (p *portSession) send(ctx context.Context, frame mapFrame) error {
	frame.session, frame.rule = p.id, 1
	return p.channelSender.send(ctx, frame)
}

// send writes the original stream identifiers, e.g. a SYN_ACK echoes the caller's tuple.
func (p *channelSender) send(ctx context.Context, frame mapFrame) error {
	for {
		p.sendMu.Lock()
		if ctx.Err() != nil {
			p.sendMu.Unlock()
			return ctx.Err()
		}
		if frame.kind != wireDATA || p.channel.BufferedAmount() <= sendLow {
			err := p.channel.Send(encodeFrame(frame))
			p.sendMu.Unlock()
			if err != nil {
				p.cancel()
			}
			return err
		}
		waiter := p.window
		p.sendMu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-waiter:
		}
	}
}

// receive routes an ordered frame, e.g. DATA stream 7 -> the seventh flow's queue.
func (p *portSession) receive(message webrtc.DataChannelMessage) {
	if message.IsString {
		return
	}
	frame, ok := decodeFrame(message.Data)
	if !ok || frame.session != p.id || frame.rule != 1 || frame.kind == wireDATAACK {
		return
	}
	p.flowMu.Lock()
	flow := p.flows[frame.stream]
	p.flowMu.Unlock()
	if flow == nil {
		return
	}
	select {
	case flow.incoming <- frame:
	default:
		// A blocked TCP writer must not block the FILE dispatcher for other streams.
		flow.cancel()
	}
}

// bridge relays an accepted local TCP connection, e.g. SOCKS greeting bytes -> UU DATA.
func (p *portSession) bridge(conn net.Conn, remotePort uint16) {
	defer conn.Close()
	ctx, cancel := context.WithCancel(p.ctx)
	defer cancel()
	id := p.next.Add(1)
	flow := &mappedFlow{cancel: cancel, incoming: make(chan mapFrame, receiveQueue)}
	p.flowMu.Lock()
	if len(p.flows) >= maxFlows || ctx.Err() != nil {
		p.flowMu.Unlock()
		return
	}
	p.flows[id] = flow
	p.flowMu.Unlock()
	defer func() {
		p.flowMu.Lock()
		delete(p.flows, id)
		p.flowMu.Unlock()
	}()
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()
	syn, _ := json.Marshal(map[string]any{"version": 1, "target_host": "127.0.0.1", "target_port": remotePort})
	if p.send(ctx, mapFrame{stream: id, kind: wireSYN, payload: syn}) != nil {
		return
	}
	defer p.send(p.ctx, mapFrame{stream: id, kind: wireFIN})
	if waitForSYNACK(ctx, flow.incoming) != nil {
		return
	}
	go writeMappedTCP(ctx, cancel, conn, flow.incoming)
	buffer := make([]byte, streamChunk)
	for p.waitWritable(ctx) == nil {
		size, err := conn.Read(buffer)
		if size > 0 && p.send(ctx, mapFrame{stream: id, kind: wireDATA, payload: buffer[:size]}) != nil {
			return
		}
		if err != nil {
			return
		}
	}
}

// waitForSYNACK completes the remote dial, e.g. ok=false -> reject that flow.
func waitForSYNACK(ctx context.Context, incoming <-chan mapFrame) error {
	timer := time.NewTimer(12 * time.Second)
	defer timer.Stop()
	select {
	case frame := <-incoming:
		var ack struct {
			OK bool `json:"ok"`
		}
		if frame.kind != wireSYNACK || json.Unmarshal(frame.payload, &ack) != nil || !ack.OK {
			return errors.New("UU 目标端口拒绝连接")
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return errors.New("UU 目标端口响应超时")
	}
}

// writeMappedTCP drains one flow's receive queue, e.g. a remote FIN closes TCP after preceding DATA.
func writeMappedTCP(ctx context.Context, cancel context.CancelFunc, conn net.Conn, incoming <-chan mapFrame) {
	defer cancel()
	for {
		select {
		case frame := <-incoming:
			if frame.kind != wireDATA {
				return
			}
			if _, err := conn.Write(frame.payload); err != nil {
				return
			}
		case <-ctx.Done():
			return
		}
	}
}
