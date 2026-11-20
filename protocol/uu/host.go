package uu

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

const hostTag = "uu-host"

var owner atomic.Pointer[HostService]

// HostOptions configures the singleton UU receiver.
type HostOptions struct {
	// Port is the local mapping target on IPv4 loopback, or zero to disable receiving.
	Port uint16 `json:"local_port,omitempty"`
	// Accounts lists the controller profiles exposed in the global auth center.
	Accounts []string `json:"accounts,omitempty"`
	// HostAccount reuses a connection profile; empty uses the receiver's separate login.
	HostAccount string `json:"host_account,omitempty"`
}

// HostService publishes the existing local UU identity independently of any outbound.
type HostService struct {
	// Adapter exposes the service type and tag to sing-box.
	boxService.Adapter
	// ctx ends the publisher and all of its accepted peers.
	ctx context.Context
	// cancel closes the publisher on box shutdown.
	cancel context.CancelFunc
	// cloud exchanges the stored credentials for a publisher room.
	cloud cloudClient
	// transport is the HTTP pool shared with publisher signaling.
	transport *http.Transport
	// network supplies the same TUN-safe ICE sockets as the outbound.
	network *physicalNet
	// account is shared across all local roles for this profile.
	account *account
	// controllers holds the separate connection profiles exposed to the panel.
	controllers map[string]*account
	// logger reports the cloud availability and room failures.
	logger log.ContextLogger
	// port is the configured local mixed inbound on 127.0.0.1.
	port uint16
	// mu protects the control server and host availability snapshot.
	mu sync.Mutex
	// control owns the global private control socket until shutdown finishes.
	control *http.Server
	// done closes after the room loop and peer cleanup finish.
	done chan struct{}
	// state is the publisher's separate availability state.
	state string
	// failure is a sanitized startup or signaling failure.
	failure string
}

var _ adapter.Service = (*HostService)(nil)

// RegisterService adds the UU receiver to the service registry, e.g. services[].type="uu".
func RegisterService(registry *boxService.Registry) {
	boxService.Register[HostOptions](registry, Type, newHostService)
}

// newHostService constructs the global receiver, e.g. local_port 10808 -> loopback mixed 10808.
func newHostService(ctx context.Context, logger log.ContextLogger, tag string, options HostOptions) (adapter.Service, error) {
	profile, err := profilePath("host-credentials.json")
	if err != nil {
		return nil, err
	}
	controllers := make(map[string]*account, len(options.Accounts)+1)
	for _, key := range append([]string{"default"}, options.Accounts...) {
		if !validAccountID(key) || key == "host" {
			return nil, errors.New("invalid uu account ID")
		}
		path, err := controllerProfilePath(key)
		if err != nil {
			return nil, err
		}
		controllers[key] = accountFor(path)
	}
	host := accountFor(profile)
	if options.HostAccount != "" {
		host = controllers[options.HostAccount]
		if host == nil {
			return nil, errors.New("uu host_account must name an existing connection account")
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	cloud, transport, network, err := newTransport(ctx, option.DialerOptions{})
	if err != nil {
		cancel()
		return nil, err
	}
	state := "disabled"
	if options.Port != 0 {
		state = "waiting_auth"
	}
	return &HostService{
		Adapter: boxService.NewAdapter(Type, tag), ctx: ctx, cancel: cancel, port: options.Port,
		cloud: cloud, transport: transport, network: network, account: host,
		controllers: controllers, logger: logger, state: state,
	}, nil
}

// Start claims the singleton once the mixed listener is up, e.g. duplicate service -> startup error.
func (h *HostService) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStatePostStart {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.ctx.Err(); err != nil {
		return err
	}
	if h.control != nil {
		return nil
	}
	if !owner.CompareAndSwap(nil, h) {
		return errors.New("only one uu host service is allowed")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", h.handleStatus)
	mux.HandleFunc("POST /login", h.handleLogin)
	mux.HandleFunc("GET /devices", h.handleDevices)
	server, err := startControlSocket(h.ctx, controlPath(hostTag), mux)
	if err != nil {
		owner.CompareAndSwap(h, nil)
		return err
	}
	h.control, h.done = server, make(chan struct{})
	if h.port == 0 {
		close(h.done)
	} else {
		go h.serve()
	}
	return nil
}

// Close ends the host before releasing ownership, e.g. reload cannot create a second publisher.
func (h *HostService) Close() error {
	h.cancel()
	h.mu.Lock()
	control, done := h.control, h.done
	h.control = nil
	h.mu.Unlock()
	if done != nil {
		<-done
	}
	if control != nil {
		_ = control.Close()
	}
	owner.CompareAndSwap(h, nil)
	h.transport.CloseIdleConnections()
	return nil
}

// handleStatus returns the global login and publisher state, e.g. online -> discoverable in UU.
func (h *HostService) handleStatus(w http.ResponseWriter, r *http.Request) {
	profile, controller := h.profile(w, r)
	if profile == nil {
		return
	}
	if controller {
		writeControlJSON(w, http.StatusOK, statusView{loginView: profile.status(), Connection: "idle"})
		return
	}
	h.mu.Lock()
	view := statusView{loginView: h.account.status(), Connection: h.state, ConnectionError: h.failure}
	h.mu.Unlock()
	writeControlJSON(w, http.StatusOK, view)
}

// handleLogin starts account login even if the box has no UU outbounds.
func (h *HostService) handleLogin(w http.ResponseWriter, r *http.Request) {
	profile, _ := h.profile(w, r)
	if profile == nil {
		return
	}
	profile.start(h.ctx, h.cloud)
	h.handleStatus(w, r)
}

// handleDevices lists a controller's devices, e.g. profile=office -> office device list.
func (h *HostService) handleDevices(w http.ResponseWriter, r *http.Request) {
	profile, controller := h.profile(w, r)
	if profile == nil {
		return
	}
	if !controller {
		writeControlJSON(w, http.StatusBadRequest, map[string]string{"error": "请选择 UU 连接账号"})
		return
	}
	serveAccountDevices(w, r, profile, h.cloud)
}

// profile bounds local auth requests to configured accounts, with empty selecting the host.
func (h *HostService) profile(w http.ResponseWriter, r *http.Request) (*account, bool) {
	key := r.URL.Query().Get("profile")
	if key == "" {
		return h.account, false
	}
	profile := h.controllers[key]
	if profile == nil {
		writeControlJSON(w, http.StatusNotFound, map[string]string{"error": "UU 连接账号不存在"})
	}
	return profile, true
}

// setState publishes a state transition, e.g. an authenticated room is reported ready by the cloud.
func (h *HostService) setState(state string, err error) {
	h.mu.Lock()
	changed := h.state != state
	h.state, h.failure = state, ""
	if err != nil {
		h.failure = err.Error()
	}
	h.mu.Unlock()
	if changed && state == "online" {
		h.logger.Info("UU host is online")
	} else if changed && err != nil && h.ctx.Err() == nil {
		h.logger.Warn("UU host: ", err)
	}
}

// serve owns publisher renewal and peer lifetimes, e.g. losing signaling keeps existing transports alive.
func (h *HostService) serve() {
	defer close(h.done)
	peers := make(map[string]*hostPeer)
	defer func() {
		for _, peer := range peers {
			peer.cancel()
		}
	}()
	for h.ctx.Err() == nil {
		credentials, err := h.account.current()
		if err != nil {
			h.setState("waiting_auth", nil)
			if !waitHost(h.ctx, time.Second) {
				return
			}
			continue
		}
		h.setState("connecting", nil)
		err = h.publish(credentials, peers)
		if errors.Is(err, errLoginExpired) {
			h.account.expire(credentials.Token)
		} else if err != nil && h.ctx.Err() == nil {
			h.setState("error", err)
		}
		pruneHostPeers(peers)
		if err != nil && !waitHost(h.ctx, 3*time.Second) {
			return
		}
	}
}

// waitHost waits with shutdown awareness, e.g. cancellation interrupts retry backoff.
func waitHost(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// hostSetup carries the authenticated control announcement for a forthcoming offer.
type hostSetup struct {
	// Transport contains the ICE servers and relay policy from UU.
	Transport controlAck
	// At bounds the lifetime of unused cloud metadata.
	At time.Time
}

// roomPacket is one serialized publisher packet or terminal transport error.
type roomPacket struct {
	// ack is the numeric Socket.IO acknowledgement, or zero for an event.
	ack int
	// payload is the event body; always avoid writing it to logs.
	payload []json.RawMessage
	// err ends the publisher signaling connection.
	err error
}

// publish runs one publisher room, e.g. lost WSS -> obtain a fresh room without closing live peers.
func (h *HostService) publish(creds credentials, peers map[string]*hostPeer) error {
	setup, finish := context.WithTimeout(h.ctx, 18*time.Second)
	defer finish()
	var response struct {
		room
		Primary string `json:"signaling_server"`
	}
	if _, err := h.cloud.request(setup, creds, http.MethodPost, "/api/v1/room/create", struct{}{}, &response); err != nil {
		return err
	}
	// The publisher endpoint is sometimes returned separately from the fallback list.
	if response.Primary != "" {
		response.Signaling = append([]string{response.Primary}, response.Signaling...)
	}
	if response.Token == "" || len(response.Signaling) == 0 {
		return errors.New("UU 云端没有返回被控端房间")
	}
	s, err := openSignal(setup, h.cloud.http, response.room)
	if err != nil {
		return err
	}
	defer s.ws.CloseNow()
	s.readTimeout = s.heartbeat
	if err = s.emit(setup, 11, "room_info"); err != nil {
		return err
	}
	roomCtx, cancel := context.WithCancel(h.ctx)
	defer cancel()
	packets := make(chan roomPacket, 16)
	go func() {
		for roomCtx.Err() == nil {
			ack, payload, err := s.packet(roomCtx)
			select {
			case packets <- roomPacket{ack, payload, err}:
			case <-roomCtx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	finish()
	pending := make(map[string]hostSetup)
	refresh := time.NewTimer(30 * time.Second)
	defer refresh.Stop()
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	now := time.Now()
	renewal := now.Add(15 * time.Minute)
	deadline := now.Add(30 * time.Second)
	lastAck, request := 11, 11
	online := false
	for {
		select {
		case <-roomCtx.Done():
			return nil
		case <-refresh.C:
			request++
			send, done := context.WithTimeout(roomCtx, 8*time.Second)
			err = s.emit(send, request, "refresh_reconnect_key")
			done()
			if err != nil {
				return err
			}
			refresh.Reset(30 * time.Second)
		case now = <-tick.C:
			alive := pruneHostPeers(peers)
			if !online && now.After(deadline) {
				return errors.New("UU 云端未确认本机上线")
			}
			if current, err := h.account.current(); err == nil && current.Token != creds.Token {
				return nil
			}
			if !alive && now.After(renewal) {
				return nil
			}
			for id, item := range pending {
				if now.Sub(item.At) > time.Minute {
					delete(pending, id)
				}
			}
		case p := <-packets:
			if p.err != nil {
				return p.err
			}
			if p.ack != 0 {
				var key struct {
					Value string `json:"reconnect_key"`
				}
				if p.ack > lastAck && p.ack <= request && len(p.payload) == 2 && rawString(p.payload[0]) == "success" &&
					json.Unmarshal(p.payload[1], &key) == nil && key.Value != "" {
					lastAck = p.ack
					refresh.Reset(5 * time.Minute)
				}
				continue
			}
			if len(p.payload) < 2 {
				continue
			}
			switch rawString(p.payload[0]) {
			case "bmsg_push":
				var update struct {
					Data struct {
						Availability string `json:"publisher_availability_status"`
					} `json:"data"`
				}
				if json.Unmarshal(p.payload[1], &update) == nil {
					switch update.Data.Availability {
					case "ready":
						online = true
						h.setState("online", nil)
					case "offline":
						// Availability can change while signaling is healthy. Recreating
						// the room here can make receivers on the same account flap.
						h.logger.Debug("UU publisher reported offline; keeping signaling open")
					}
				}
			case "be-controlled":
				registerHostOffer(p.payload, pending)
			case "soac":
				h.handleHostSOAC(roomCtx, s, p.payload[1], pending, peers)
			case "released", "left", "leave":
				var ended struct {
					ID   string `json:"ice_id"`
					Data *struct {
						ID string `json:"ice_id"`
					} `json:"data"`
				}
				if json.Unmarshal(p.payload[1], &ended) == nil {
					if ended.ID == "" && ended.Data != nil {
						ended.ID = ended.Data.ID
					}
					if peer := peers[ended.ID]; peer != nil {
						peer.cancel()
						delete(peers, ended.ID)
					} else if ended.ID == "" && rawString(p.payload[0]) != "released" {
						return nil
					}
				}
			}
		}
	}
}

// registerHostOffer associates the cloud's capture type with its ICE key, e.g. 9 -> port-map authorization.
func registerHostOffer(payload []json.RawMessage, pending map[string]hostSetup) {
	var transport controlAck
	if json.Unmarshal(payload[1], &transport) != nil {
		return
	}
	var attached string
	if len(payload) == 3 {
		attached = rawString(payload[2])
	} else {
		var header struct {
			Data string `json:"app_data"`
		}
		_ = json.Unmarshal(payload[1], &header)
		attached = header.Data
	}
	raw, err := base64.StdEncoding.DecodeString(attached)
	if err != nil {
		return
	}
	if len(raw) > 0 && raw[0] == 4 {
		raw = raw[1:]
	}
	if wireNumber(raw, 1) != 9 {
		delete(pending, transport.IceID)
		return
	}
	if len(pending) < 32 {
		pending[transport.IceID] = hostSetup{transport, time.Now()}
	}
}

// pruneHostPeers releases ended peers and reports whether any carrier is active.
func pruneHostPeers(peers map[string]*hostPeer) bool {
	for key, peer := range peers {
		if peer.ctx.Err() != nil {
			delete(peers, key)
		}
	}
	return len(peers) != 0
}
