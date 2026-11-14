package include

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// TestCFDestinationPayload verifies every supported address family has stable wire bytes.
//
// Example: `example.com:443` retains its domain instead of resolving locally.
func TestCFDestinationPayload(t *testing.T) {
	tests := []struct {
		name        string
		destination string
		expected    []byte
	}{
		{"ipv4", "127.0.0.1:22", []byte{1, 127, 0, 0, 1, 0, 22}},
		{"ipv6", "[2001:db8::1]:443", []byte{4, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0xbb}},
		{"domain", "example.com:443", append([]byte{3, 11}, append([]byte("example.com"), 1, 0xbb)...)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := cfDestinationPayload(M.ParseSocksaddr(test.destination))
			if err != nil {
				t.Fatalf("encode destination: %v", err)
			}
			if !bytes.Equal(actual, test.expected) {
				t.Fatalf("unexpected payload: %x != %x", actual, test.expected)
			}
		})
	}
}

// TestCFDestinationPayloadRejectsInvalidInput verifies malformed targets fail before OPEN.
//
// Example: a zero port can never become a daemon-side connection attempt.
func TestCFDestinationPayloadRejectsInvalidInput(t *testing.T) {
	for _, destination := range []M.Socksaddr{
		{},
		M.ParseSocksaddr("example.com:0"),
		M.ParseSocksaddr("bad name:443"),
	} {
		if _, err := cfDestinationPayload(destination); err == nil {
			t.Fatalf("expected invalid destination %q", destination.String())
		}
	}
}

// TestCFMuxEndpointNormalizesLegacyDiscovery verifies discovery changes only its transport path.
//
// Example: `/tcp?port=22&code=x` becomes `/mux?code=x`.
func TestCFMuxEndpointNormalizesLegacyDiscovery(t *testing.T) {
	actual, err := cfMuxEndpoint("wss://edge.example/tcp?port=22&code=secret")
	if err != nil {
		t.Fatalf("normalize endpoint: %v", err)
	}
	if actual != "wss://edge.example/mux?code=secret" {
		t.Fatalf("unexpected endpoint %q", actual)
	}
	for _, invalid := range []string{"https://edge.example/tcp?code=x", "wss:///tcp?code=x", "wss://edge.example/tcp"} {
		if _, err = cfMuxEndpoint(invalid); err == nil {
			t.Fatalf("expected invalid endpoint %q", invalid)
		}
	}
}

// TestCFHexIdentifier verifies namespace IDs are exact hexadecimal values.
//
// Example: an arbitrary 32-character title does not bypass namespace lookup.
func TestCFHexIdentifier(t *testing.T) {
	if !isCFHexIdentifier("0123456789abcdefABCDEF0123456789") {
		t.Fatal("valid identifier rejected")
	}
	for _, invalid := range []string{"", "0123", "gggggggggggggggggggggggggggggggg"} {
		if isCFHexIdentifier(invalid) {
			t.Fatalf("invalid identifier accepted: %q", invalid)
		}
	}
}

// TestCFColoFromRay verifies the panel receives only exact Cloudflare POP codes.
//
// Example: a full CF-Ray value exposes HKG while malformed suffixes stay hidden.
func TestCFColoFromRay(t *testing.T) {
	for input, expected := range map[string]string{
		"8abc-HKG":        "HKG",
		"8abc-hkg":        "HKG",
		" 8abc-TPE ":      "TPE",
		"8abc-SIN, other": "SIN",
		"":                "",
		"8abc-HK":         "",
		"8abc-HKG1":       "",
		"8abc-12A":        "",
	} {
		if actual := cfColoFromRay(input); actual != expected {
			t.Fatalf("ray %q: got %q, want %q", input, actual, expected)
		}
	}
}

// TestCFByteFairScheduler verifies service tracks bytes rather than frame count.
//
// Example: 1KiB interactive DATA catches up against a 64KiB bulk frame.
func TestCFByteFairScheduler(t *testing.T) {
	flows := make(map[uint32]*cfFlowState)
	virtualTime := uint64(0)
	enqueueCFTestCommand(flows, &virtualTime, 1, 64*1024)
	enqueueCFTestCommand(flows, &virtualTime, 3, 1024)
	if command := popCFData(flows, &virtualTime); command == nil || command.streamID != 1 {
		t.Fatalf("deterministic first service failed: %#v", command)
	}
	if command := popCFData(flows, &virtualTime); command == nil || command.streamID != 3 {
		t.Fatalf("interactive flow did not receive service: %#v", command)
	}
	for index := 0; index < 63; index++ {
		enqueueCFTestCommand(flows, &virtualTime, 3, 1024)
		if command := popCFData(flows, &virtualTime); command == nil || command.streamID != 3 {
			t.Fatalf("interactive catch-up stopped at %d", index)
		}
	}
	enqueueCFTestCommand(flows, &virtualTime, 1, 64*1024)
	enqueueCFTestCommand(flows, &virtualTime, 3, 1024)
	if command := popCFData(flows, &virtualTime); command == nil || command.streamID != 1 {
		t.Fatalf("bulk flow starved after equal byte service: %#v", command)
	}
}

// enqueueCFTestCommand adds one scheduler command without carrier I/O.
//
// Example: stream 3 and length 1024 produces one pending 1KiB DATA command.
func enqueueCFTestCommand(flows map[uint32]*cfFlowState, virtualTime *uint64, streamID uint32, length int) {
	applyCFDataEvent(flows, virtualTime, cfDataEvent{
		kind: cfDataEnqueue,
		command: &cfDataCommand{
			streamID:  streamID,
			payload:   make([]byte, length),
			delivered: make(chan error, 1),
		},
	})
}

// TestCFIdleFlowRejoinsAtCurrentVirtualTime verifies bursty flows cannot bank old priority.
//
// Example: a long-idle SSH stream rejoins now, not at its historic zero-byte position.
func TestCFIdleFlowRejoinsAtCurrentVirtualTime(t *testing.T) {
	flows := make(map[uint32]*cfFlowState)
	virtualTime := uint64(0)
	enqueueCFTestCommand(flows, &virtualTime, 1, 4096)
	_ = popCFData(flows, &virtualTime)
	applyCFDataEvent(flows, &virtualTime, cfDataEvent{kind: cfDataIdle, streamID: 1})
	enqueueCFTestCommand(flows, &virtualTime, 3, 1024)
	_ = popCFData(flows, &virtualTime)
	enqueueCFTestCommand(flows, &virtualTime, 1, 1)
	if flows[1].virtualFinish != virtualTime {
		t.Fatalf("idle flow banked priority: finish=%d now=%d", flows[1].virtualFinish, virtualTime)
	}
}

// TestCFWindowBlocksAndResumes verifies source progress stops at both advertised windows.
//
// Example: zero aggregate credit blocks reserveSend until WINDOW_UPDATE restores it.
func TestCFWindowBlocksAndResumes(t *testing.T) {
	session, stream, cancel := newCFTestWindowState(4, 4)
	defer cancel()
	amount, err := session.reserveSend(stream, 4, time.Time{})
	if err != nil || amount != 4 {
		t.Fatalf("initial reserve: amount=%d err=%v", amount, err)
	}
	result := make(chan error, 1)
	go func() {
		_, reserveErr := session.reserveSend(stream, 1, time.Now().Add(time.Second))
		result <- reserveErr
	}()
	select {
	case err = <-result:
		t.Fatalf("zero window did not block: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if err = session.updateStreamWindow(stream.id, 1); err != nil {
		t.Fatalf("restore stream window: %v", err)
	}
	if err = session.updateConnectionWindow(1); err != nil {
		t.Fatalf("restore connection window: %v", err)
	}
	select {
	case err = <-result:
		if err != nil {
			t.Fatalf("reserve did not resume: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("reserve remained blocked after window update")
	}
}

// newCFTestWindowState creates an isolated session and stream for credit tests.
//
// Example: stream=4 and connection=8 yields a 4-byte first reservation.
func newCFTestWindowState(streamWindow uint32, connectionWindow uint32) (*cfSession, *cfMuxConn, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	session := &cfSession{
		ctx:                    ctx,
		cancel:                 cancel,
		streams:                make(map[uint32]*cfMuxConn),
		associations:           make(map[uint32]*cfPacketConn),
		remoteStreamWindow:     streamWindow,
		remoteMaximumFrame:     streamWindow,
		remoteConnectionWindow: connectionWindow,
		sendConnectionWindow:   connectionWindow,
		sendWindowNotify:       make(chan struct{}, 1),
	}
	stream := &cfMuxConn{session: session, id: 1, sendWindow: streamWindow, inboundNotify: make(chan struct{}, 1)}
	session.streams[stream.id] = stream
	return session, stream, cancel
}

// TestCFWindowDeadlineAndCloseWake verifies blocked operations terminate predictably.
//
// Example: a closed stream wakes immediately while a live zero window reaches its deadline.
func TestCFWindowDeadlineAndCloseWake(t *testing.T) {
	session, stream, cancel := newCFTestWindowState(1, 0)
	defer cancel()
	_, err := session.reserveSend(stream, 1, time.Now().Add(20*time.Millisecond))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected deadline, got %v", err)
	}
	stream.closeRemote(io.ErrUnexpectedEOF)
	_, err = session.reserveSend(stream, 1, time.Time{})
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected close reason, got %v", err)
	}
}

// TestCFReceiveWindowAndFIN verifies queued bytes drain before EOF and enforce credit.
//
// Example: DATA `abc` followed by FIN returns three bytes and then io.EOF.
func TestCFReceiveWindowAndFIN(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session := &cfSession{ctx: ctx, receiveConnectionWindow: 3, sendWindowNotify: make(chan struct{}, 1)}
	stream := &cfMuxConn{session: session, receiveWindow: 3, inboundNotify: make(chan struct{}, 1)}
	if err := stream.receive([]byte("abc")); err != nil {
		t.Fatalf("receive DATA: %v", err)
	}
	if err := stream.receive([]byte("x")); err == nil {
		t.Fatal("receive window overflow accepted")
	}
	stream.receiveFIN()
	buffer := make([]byte, 3)
	if read, err := stream.Read(buffer); err != nil || read != 3 || string(buffer) != "abc" {
		t.Fatalf("drain DATA: read=%d data=%q err=%v", read, buffer, err)
	}
	if _, err := stream.Read(buffer); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF after drain, got %v", err)
	}
}

// TestCFPacketConnPreservesBoundaries verifies UDP packets do not merge or split silently.
//
// Example: two daemon packets are read as two independent PacketConn operations.
func TestCFPacketConnPreservesBoundaries(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	connection := &cfPacketConn{
		session:      &cfSession{ctx: ctx, closeErr: net.ErrClosed},
		destination:  M.ParseSocksaddr("1.1.1.1:53"),
		inbound:      make(chan []byte, 2),
		closedNotify: make(chan struct{}),
	}
	connection.inbound <- []byte("one")
	connection.inbound <- []byte("two")
	for _, expected := range []string{"one", "two"} {
		buffer := make([]byte, 8)
		read, address, err := connection.ReadFrom(buffer)
		if err != nil || string(buffer[:read]) != expected || address.String() != "1.1.1.1:53" {
			t.Fatalf("packet boundary: read=%d data=%q addr=%v err=%v", read, buffer[:read], address, err)
		}
	}
}
