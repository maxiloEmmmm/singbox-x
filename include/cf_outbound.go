package include

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	stdTLS "crypto/tls"
	"encoding/binary"
	stdJSON "encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxOutbound "github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/ws"
	"github.com/sagernet/ws/wsutil"
	"gopkg.in/yaml.v3"
)

const (
	cfOutboundType                   = "cf"
	cfMuxVersion              uint16 = 1
	cfStreamWindow                   = 4 * 1024 * 1024
	cfConnectionWindow               = 16 * 1024 * 1024
	cfMaximumFrame                   = 65_507
	cfMaximumStreams                 = 256
	cfWindowThreshold                = 64 * 1024
	cfControlBurst                   = 32
	cfControlCapacity                = 256
	cfDataCapacity                   = 256
	cfDatagramCapacity               = 256
	cfDatagramReceiveCapacity        = 64
	cfHeartbeatInterval              = 30 * time.Second
	cfAPITimeout                     = 10 * time.Second
	cfAPIBase                        = "https://api.cloudflare.com/client/v4"
	cfRuntimeStatusDirectory         = "/run/sboxctl/cf-outbound"
)

const (
	cfOpHello byte = iota + 1
	cfOpOpen
	cfOpOpenOK
	cfOpOpenError
	cfOpData
	cfOpFin
	cfOpReset
	cfOpWindowUpdate
	cfOpConnectionWindowUpdate
	cfOpDatagramOpen
	cfOpDatagramOpenOK
	cfOpDatagramOpenError
	cfOpDatagram
	cfOpDatagramClose
)

var cfRuntimeStatusAccess sync.Mutex

// cfOutboundOptions configures direct destination transport through the Rust daemon.
//
// Example: `kv_key: cfp/demo` resolves one rotating TryCloudflare endpoint.
type cfOutboundOptions struct {
	// DialerOptions controls the physical Cloudflare and KV network path.
	option.DialerOptions
	// Endpoint is an optional fixed `wss://host/tcp?code=...` URL.
	Endpoint string `json:"endpoint,omitempty"`
	// KVKey is the complete Workers KV key used by rotating daemon endpoints.
	KVKey string `json:"kv_key,omitempty"`
	// ConfigPath overrides CFP_CONFIG only for this outbound.
	ConfigPath string `json:"config_path,omitempty"`
}

// cfOutbound implements sing-box TCP and UDP dialing over one shared mux carrier.
//
// Example: twenty routed TCP connections share one WSS while retaining independent windows.
type cfOutbound struct {
	// Adapter exposes type, tag, network support, and detour dependencies.
	boxOutbound.Adapter
	// logger records carrier creation and terminal failures without secrets.
	logger logger.ContextLogger
	// ctx ends physical and logical work when the owning sing-box instance closes.
	ctx context.Context
	// physicalDialer bypasses the TUN according to normal sing-box dialer options.
	physicalDialer N.Dialer
	// resolver supplies fixed or KV-backed authenticated WSS endpoints.
	resolver *cfEndpointResolver
	// tag identifies this outbound in the sboxctl runtime status bridge.
	tag string
	// sessionAccess serializes lazy creation and stale-session replacement.
	sessionAccess sync.Mutex
	// session is the sole live mux carrier, replaced after terminal failure.
	session *cfSession
	// closed prevents new streams after sing-box shutdown.
	closed bool
}

// cfEndpointResolver resolves and caches a daemon endpoint without exposing its token.
//
// Example: a failed WSS dial forces one fresh KV read before retrying.
type cfEndpointResolver struct {
	// fixed is returned without Cloudflare API access when configured.
	fixed string
	// kvKey is the complete value key such as `cfp/demo`.
	kvKey string
	// accountID identifies the Cloudflare account owning the namespace.
	accountID string
	// token authenticates Cloudflare API reads and is never logged.
	token string
	// namespace is either a stable ID or a human-readable title.
	namespace string
	// namespaceID caches title resolution after the first successful request.
	namespaceID string
	// client uses the outbound's physical dialer to avoid transparent routing recursion.
	client *http.Client
	// access protects cached endpoint and namespace state.
	access sync.Mutex
	// cached retains the latest successfully validated WSS endpoint.
	cached string
}

// cfReporterConfig is the CFP YAML subset consumed by endpoint discovery.
//
// Example: only a `cf_kv` reporter is accepted for KV-backed outbound operation.
type cfReporterConfig struct {
	// Reporter contains Cloudflare KV credentials and namespace selection.
	Reporter *cfReporter `yaml:"reporter"`
}

// cfReporter describes the existing `/etc/cfp/config.yaml` reporter section.
//
// Example: token_env `CF_TOKEN` resolves the bearer token from systemd environment.
type cfReporter struct {
	// Type must be `cf_kv`.
	Type string `yaml:"type"`
	// AccountID is the Cloudflare account owning the namespace.
	AccountID string `yaml:"account_id"`
	// Token is a literal API bearer token.
	Token string `yaml:"token"`
	// TokenEnv names the environment variable containing the API token.
	TokenEnv string `yaml:"token_env"`
	// Namespace is a KV namespace ID or title.
	Namespace string `yaml:"namespace"`
}

// cfKVEndpoint is the minimal daemon record read from Workers KV.
//
// Example: `cf` and `code` build `wss://<cf>/mux?code=<code>`.
type cfKVEndpoint struct {
	// CF is the active TryCloudflare hostname.
	CF string `json:"cf"`
	// Code is the daemon's current access UUID.
	Code string `json:"code"`
}

// cfAPIResponse decodes Cloudflare namespace-list responses.
//
// Example: `success=true` plus result entries permits title lookup.
type cfAPIResponse struct {
	// Success reports Cloudflare API-level success.
	Success bool `json:"success"`
	// Result contains namespace records for the requested page.
	Result []cfNamespace `json:"result"`
	// Errors contains safe human-readable API failures.
	Errors []cfAPIError `json:"errors"`
}

// cfNamespace maps one Cloudflare namespace title to its stable identifier.
//
// Example: title `proxy` resolves to its 32-character ID.
type cfNamespace struct {
	// ID is the stable namespace identifier used by value reads.
	ID string `json:"id"`
	// Title is the configured human-readable name.
	Title string `json:"title"`
}

// cfAPIError retains one Cloudflare error message without response internals.
//
// Example: an invalid token produces a message used in the constructor error.
type cfAPIError struct {
	// Message describes the API failure.
	Message string `json:"message"`
}

// cfRuntimeStatus is the credential-free state exposed to the local panel.
//
// Example: a successful HKG handshake records tag, colo, connection state, and time.
type cfRuntimeStatus struct {
	// Tag identifies the sing-box outbound that owns this carrier.
	Tag string `json:"tag"`
	// Colo is the three-character Cloudflare POP parsed from CF-Ray.
	Colo string `json:"colo"`
	// Connected reports whether this exact carrier is currently live.
	Connected bool `json:"connected"`
	// ConnectedAt is the last successful WSS handshake time.
	ConnectedAt string `json:"connected_at"`
}

// registerCFOutbound adds the custom type to sing-box's per-context registry.
//
// Example: config `type: cf` selects newCFOutbound.
func registerCFOutbound(registry *boxOutbound.Registry) {
	boxOutbound.Register[cfOutboundOptions](registry, cfOutboundType, newCFOutbound)
}

// newCFOutbound validates discovery and creates a lazy shared-carrier outbound.
//
// Example: KV config is parsed at startup while WSS dialing waits for the first route.
func newCFOutbound(ctx context.Context, _ adapter.Router, outboundLogger log.ContextLogger, tag string, options cfOutboundOptions) (adapter.Outbound, error) {
	if (options.Endpoint == "") == (options.KVKey == "") {
		return nil, fmt.Errorf("cf outbound must set exactly one of endpoint or kv_key")
	}
	physicalDialer, err := dialer.New(ctx, options.DialerOptions, true)
	if err != nil {
		return nil, err
	}
	resolver, err := newCFEndpointResolver(options, physicalDialer)
	if err != nil {
		return nil, err
	}
	return &cfOutbound{
		Adapter:        boxOutbound.NewAdapterWithDialerOptions(cfOutboundType, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		logger:         outboundLogger,
		ctx:            ctx,
		physicalDialer: physicalDialer,
		resolver:       resolver,
		tag:            tag,
	}, nil
}

// newCFEndpointResolver builds fixed or KV discovery using the existing CFP configuration.
//
// Example: an empty config_path follows CFP_CONFIG, /etc/cfp, then the user path.
func newCFEndpointResolver(options cfOutboundOptions, physicalDialer N.Dialer) (*cfEndpointResolver, error) {
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return physicalDialer.DialContext(ctx, network, M.ParseSocksaddr(address))
		},
	}
	resolver := &cfEndpointResolver{
		fixed: options.Endpoint,
		kvKey: options.KVKey,
		client: &http.Client{
			Transport: transport,
			Timeout:   cfAPITimeout,
		},
	}
	if resolver.fixed != "" {
		_, err := cfMuxEndpoint(resolver.fixed)
		return resolver, err
	}
	configPath := options.ConfigPath
	if configPath == "" {
		configPath = os.Getenv("CFP_CONFIG")
	}
	if configPath == "" {
		const systemConfigPath = "/etc/cfp/config.yaml"
		if _, err := os.Stat(systemConfigPath); err == nil {
			configPath = systemConfigPath
		} else {
			home, homeErr := os.UserHomeDir()
			if homeErr != nil {
				return nil, fmt.Errorf("resolve CFP config home: %w", homeErr)
			}
			configPath = filepath.Join(home, ".config", "cfp", "config.yaml")
		}
	}
	content, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read CFP config %s: %w", configPath, err)
	}
	var config cfReporterConfig
	if err = yaml.Unmarshal(content, &config); err != nil {
		return nil, fmt.Errorf("parse CFP config %s: %w", configPath, err)
	}
	if config.Reporter == nil || config.Reporter.Type != "cf_kv" {
		return nil, fmt.Errorf("CFP config reporter.type must be cf_kv")
	}
	if (config.Reporter.Token == "") == (config.Reporter.TokenEnv == "") {
		return nil, fmt.Errorf("CFP reporter must set exactly one of token or token_env")
	}
	resolver.accountID = strings.TrimSpace(config.Reporter.AccountID)
	if !isCFHexIdentifier(resolver.accountID) {
		return nil, fmt.Errorf("CFP reporter.account_id must be a 32-character hexadecimal ID")
	}
	resolver.token = config.Reporter.Token
	if config.Reporter.TokenEnv != "" {
		resolver.token = os.Getenv(config.Reporter.TokenEnv)
	}
	resolver.namespace = strings.TrimSpace(config.Reporter.Namespace)
	if resolver.token == "" || resolver.namespace == "" || resolver.kvKey == "" {
		return nil, fmt.Errorf("CFP token, namespace, and cf kv_key must be non-empty")
	}
	return resolver, nil
}

// endpoint returns a cached endpoint or forces one fresh KV value read.
//
// Example: carrier failure calls `endpoint(true)` before its single reconnect attempt.
func (r *cfEndpointResolver) endpoint(ctx context.Context, force bool) (string, error) {
	r.access.Lock()
	defer r.access.Unlock()
	if r.fixed != "" {
		return cfMuxEndpoint(r.fixed)
	}
	if !force && r.cached != "" {
		return r.cached, nil
	}
	namespaceID, err := r.resolveNamespaceLocked(ctx)
	if err != nil {
		return "", err
	}
	parts := strings.Split(r.kvKey, "/")
	for _, part := range parts {
		if part == "" {
			return "", fmt.Errorf("cf kv_key contains an empty path segment")
		}
	}
	escaped := make([]string, len(parts))
	for index, part := range parts {
		escaped[index] = url.PathEscape(part)
	}
	endpoint := fmt.Sprintf("%s/accounts/%s/storage/kv/namespaces/%s/values/%s", cfAPIBase, r.accountID, namespaceID, strings.Join(escaped, "/"))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Authorization", "Bearer "+r.token)
	response, err := r.client.Do(request)
	if err != nil {
		return "", fmt.Errorf("read Cloudflare KV endpoint: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("read Cloudflare KV endpoint: HTTP %s", response.Status)
	}
	var value cfKVEndpoint
	if err = stdJSON.NewDecoder(response.Body).Decode(&value); err != nil {
		return "", fmt.Errorf("decode Cloudflare KV endpoint: %w", err)
	}
	resolved, err := cfMuxEndpoint("wss://" + strings.TrimSpace(value.CF) + "/tcp?code=" + url.QueryEscape(strings.TrimSpace(value.Code)))
	if err != nil {
		return "", err
	}
	r.cached = resolved
	return resolved, nil
}

// resolveNamespaceLocked resolves one namespace title once while resolver access is held.
//
// Example: a 32-character hexadecimal namespace bypasses list pagination.
func (r *cfEndpointResolver) resolveNamespaceLocked(ctx context.Context) (string, error) {
	if r.namespaceID != "" {
		return r.namespaceID, nil
	}
	if isCFHexIdentifier(r.namespace) {
		r.namespaceID = r.namespace
		return r.namespaceID, nil
	}
	for page := 1; ; page++ {
		endpoint := fmt.Sprintf("%s/accounts/%s/storage/kv/namespaces?page=%d&per_page=1000", cfAPIBase, r.accountID, page)
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return "", err
		}
		request.Header.Set("Authorization", "Bearer "+r.token)
		response, err := r.client.Do(request)
		if err != nil {
			return "", fmt.Errorf("list Cloudflare KV namespaces: %w", err)
		}
		var body cfAPIResponse
		decodeErr := stdJSON.NewDecoder(response.Body).Decode(&body)
		response.Body.Close()
		if decodeErr != nil {
			return "", fmt.Errorf("decode Cloudflare namespace list: %w", decodeErr)
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 || !body.Success {
			message := response.Status
			if len(body.Errors) > 0 {
				message = body.Errors[0].Message
			}
			return "", fmt.Errorf("list Cloudflare namespaces: %s", message)
		}
		for _, namespace := range body.Result {
			if namespace.Title == r.namespace {
				r.namespaceID = namespace.ID
				return r.namespaceID, nil
			}
		}
		if len(body.Result) < 1000 {
			return "", fmt.Errorf("Cloudflare namespace %q not found", r.namespace)
		}
	}
}

// isCFHexIdentifier validates the exact Cloudflare namespace identifier form.
//
// Example: 32 lowercase or uppercase hexadecimal characters return true.
func isCFHexIdentifier(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, character := range value {
		if character >= '0' && character <= '9' || character >= 'a' && character <= 'f' || character >= 'A' && character <= 'F' {
			continue
		}
		return false
	}
	return true
}

// cfMuxEndpoint converts legacy `/tcp` discovery URLs into direct mux URLs.
//
// Example: `wss://host/tcp?code=x` becomes `wss://host/mux?code=x`.
func cfMuxEndpoint(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "wss" || parsed.Hostname() == "" {
		return "", fmt.Errorf("invalid cf WSS endpoint")
	}
	code := parsed.Query().Get("code")
	if code == "" {
		return "", fmt.Errorf("cf WSS endpoint is missing code")
	}
	parsed.Path = "/mux"
	query := parsed.Query()
	query.Del("port")
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

// cfColoFromRay extracts one Cloudflare POP code from a CF-Ray response header.
//
// Example: `8abc-HKG` returns `HKG`, while a malformed header returns empty.
func cfColoFromRay(ray string) string {
	ray = strings.TrimSpace(strings.SplitN(ray, ",", 2)[0])
	separator := strings.LastIndexByte(ray, '-')
	if separator < 0 {
		return ""
	}
	colo := strings.ToUpper(strings.TrimSpace(ray[separator+1:]))
	if len(colo) != 3 {
		return ""
	}
	for _, character := range colo {
		if character < 'A' || character > 'Z' {
			return ""
		}
	}
	return colo
}

// writeRuntimeStatus publishes this carrier's credential-free panel state atomically.
//
// Example: a closed HKG carrier retains HKG and changes connected to false.
func (s *cfSession) writeRuntimeStatus(connected bool) error {
	return writeCFRuntimeStatus(cfRuntimeStatus{
		Tag:         s.statusTag,
		Colo:        s.statusColo,
		Connected:   connected,
		ConnectedAt: s.statusConnectedAt,
	})
}

// writeCFRuntimeStatus replaces one tag state without exposing endpoint credentials.
//
// Example: tag `static-cf-main` maps to a stable hash-named JSON file under /run.
func writeCFRuntimeStatus(status cfRuntimeStatus) error {
	if strings.TrimSpace(status.Tag) == "" {
		return fmt.Errorf("CF runtime status tag is empty")
	}
	cfRuntimeStatusAccess.Lock()
	defer cfRuntimeStatusAccess.Unlock()
	if err := os.MkdirAll(cfRuntimeStatusDirectory, 0o755); err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(status.Tag))
	targetPath := filepath.Join(cfRuntimeStatusDirectory, fmt.Sprintf("%x.json", digest[:8]))
	if !status.Connected {
		content, readErr := os.ReadFile(targetPath)
		if readErr == nil {
			var current cfRuntimeStatus
			if stdJSON.Unmarshal(content, &current) == nil && current.ConnectedAt != status.ConnectedAt {
				// 触发条件：旧载体在同 tag 的新载体已发布后才完成关闭。
				// 不能覆盖常规路径：旧 false 会让面板误报新 WSS 已断开。
				// 防止副作用：只允许创建该文件的同一代载体写入断开状态。
				return nil
			}
		}
	}
	payload, err := stdJSON.Marshal(status)
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	temporary, err := os.CreateTemp(cfRuntimeStatusDirectory, ".status-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err = temporary.Chmod(0o644); err == nil {
		_, err = temporary.Write(payload)
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temporaryPath, targetPath)
}

// cfFrame is one mux message carried by exactly one WebSocket binary frame.
//
// Example: DATA for stream 3 stores opcode 5, identifier 3, and opaque bytes.
type cfFrame struct {
	// opcode selects lifecycle, DATA, window, or datagram behavior.
	opcode byte
	// streamID identifies a TCP stream or UDP association; zero is connection-wide.
	streamID uint32
	// payload contains opcode-specific bytes after the common five-byte header.
	payload []byte
}

// cfControlCommand optionally waits for physical carrier handoff.
//
// Example: OPEN uses delivered to prove it precedes later DATA.
type cfControlCommand struct {
	// frame is the control message to serialize.
	frame cfFrame
	// delivered receives the carrier write result when ordering proof is required.
	delivered chan error
}

// cfDataCommand is one window-charged DATA frame awaiting fair service.
//
// Example: one stream can retain at most one command while Write waits for delivered.
type cfDataCommand struct {
	// streamID owns the payload and virtual service accounting.
	streamID uint32
	// payload is copied from the caller before asynchronous carrier handoff.
	payload []byte
	// delivered resolves after carrier write or scheduler cancellation.
	delivered chan error
}

// cfDataEvent mutates fair scheduler state in writer order.
//
// Example: remove cancels pending DATA before RESET is emitted.
type cfDataEvent struct {
	// kind is enqueue, idle, or remove.
	kind byte
	// command is present only for enqueue events.
	command *cfDataCommand
	// streamID selects idle or removal state.
	streamID uint32
	// done acknowledges completed removal.
	done chan struct{}
}

const (
	cfDataEnqueue byte = iota + 1
	cfDataIdle
	cfDataRemove
)

// cfFlowState retains byte-fair scheduling debt across consecutive writes.
//
// Example: a 64KiB frame advances virtualFinish 64 times farther than 1KiB.
type cfFlowState struct {
	// virtualFinish is the total byte service charged to this active flow.
	virtualFinish uint64
	// pending is the flow's sole command eligible for selection.
	pending *cfDataCommand
	// active distinguishes a continuous writer from an idle rejoin.
	active bool
}

// cfSession owns one shared WSS, stream registry, windows, and writer scheduler.
//
// Example: carrier failure closes every logical connection and wakes blocked operations.
type cfSession struct {
	// ctx is cancelled exactly once when the carrier terminates.
	ctx context.Context
	// cancel terminates reader, writer, and all logical waiters.
	cancel context.CancelFunc
	// conn is the upgraded raw WebSocket transport.
	conn net.Conn
	// wsWrite serializes binary, pong, and heartbeat frames.
	wsWrite sync.Mutex
	// control carries bounded-priority lifecycle and window frames.
	control chan cfControlCommand
	// data carries per-stream fair scheduler events.
	data chan cfDataEvent
	// datagrams carries lossy UDP frames isolated from control capacity.
	datagrams chan cfFrame
	// streamsAccess protects TCP and UDP logical state maps.
	streamsAccess sync.RWMutex
	// streams maps active TCP stream identifiers.
	streams map[uint32]*cfMuxConn
	// associations maps active UDP association identifiers.
	associations map[uint32]*cfPacketConn
	// nextID allocates odd client identifiers without collision.
	nextID atomic.Uint32
	// remoteAccess protects negotiated limits and send windows.
	remoteAccess sync.Mutex
	// remoteReady closes after exactly one compatible HELLO.
	remoteReady chan struct{}
	// remoteReadyOnce protects close of remoteReady.
	remoteReadyOnce sync.Once
	// remoteStreamWindow seeds each newly opened stream.
	remoteStreamWindow uint32
	// remoteMaximumFrame limits DATA and DATAGRAM payloads.
	remoteMaximumFrame uint32
	// remoteMaximumStreams bounds active logical identifiers.
	remoteMaximumStreams uint32
	// sendConnectionWindow is aggregate peer-advertised credit.
	sendConnectionWindow uint32
	// remoteConnectionWindow is the maximum aggregate credit invariant.
	remoteConnectionWindow uint32
	// sendWindowNotify wakes blocked stream writers after any update.
	sendWindowNotify chan struct{}
	// receiveAccess protects aggregate incoming connection credit.
	receiveAccess sync.Mutex
	// receiveConnectionWindow is remaining locally advertised aggregate credit.
	receiveConnectionWindow uint32
	// receiveConnectionPending accumulates consumed credit before update.
	receiveConnectionPending uint32
	// closed marks terminal cleanup and makes Close idempotent.
	closed atomic.Bool
	// closeErrAccess protects the stable terminal reason.
	closeErrAccess sync.Mutex
	// closeErr retains a stable reason for logical connection errors.
	closeErr error
	// statusTag identifies this carrier in the runtime status directory.
	statusTag string
	// statusColo is the Cloudflare POP parsed from this WSS handshake.
	statusColo string
	// statusConnectedAt retains the successful handshake timestamp across disconnect.
	statusConnectedAt string
}

// cfBufferedConn preserves WebSocket bytes already read with the HTTP response.
//
// Example: an immediate daemon HELLO buffered by ws.Dial is read before the socket.
type cfBufferedConn struct {
	// Conn is the upgraded physical transport.
	net.Conn
	// reader drains handshake-buffered bytes before falling back to Conn.
	reader *bufio.Reader
}

// Read drains buffered WebSocket bytes and then delegates to the physical connection.
//
// Example: a buffered HELLO frame is never lost after HTTP upgrade.
func (c *cfBufferedConn) Read(payload []byte) (int, error) {
	if c.reader != nil && c.reader.Buffered() > 0 {
		return c.reader.Read(payload)
	}
	c.reader = nil
	return c.Conn.Read(payload)
}

// cfRemoteAddr is a stable logical address returned by mux net.Conn implementations.
//
// Example: RemoteAddr renders the original destination rather than Cloudflare.
type cfRemoteAddr struct {
	// network is `tcp` or `udp`.
	network string
	// address is the original destination string.
	address string
}

// Network returns the logical transport family.
//
// Example: a stream address returns `tcp`.
func (a cfRemoteAddr) Network() string { return a.network }

// String returns the original destination text.
//
// Example: an IPv6 target is rendered with brackets and port.
func (a cfRemoteAddr) String() string { return a.address }

// cfMuxConn implements one flow-controlled TCP stream over the shared session.
//
// Example: blocked Write stops sing-box's copy loop after at most its current buffer.
type cfMuxConn struct {
	// session owns carrier and aggregate windows.
	session *cfSession
	// id is the stable odd logical stream identifier.
	id uint32
	// destination is exposed through RemoteAddr.
	destination M.Socksaddr
	// writeAccess serializes DATA, FIN, and RESET ordering.
	writeAccess sync.Mutex
	// stateAccess protects inbound bytes, deadlines, and lifecycle state.
	stateAccess sync.Mutex
	// inbound retains received bytes up to the advertised stream window.
	inbound bytes.Buffer
	// inboundNotify wakes Read after DATA, FIN, RESET, or deadline change.
	inboundNotify chan struct{}
	// sendWindow is peer-advertised stream credit under session.remoteAccess.
	sendWindow uint32
	// receiveWindow is remaining local credit under session.receiveAccess.
	receiveWindow uint32
	// receivePending accumulates consumed stream bytes before WINDOW_UPDATE.
	receivePending uint32
	// remoteFIN becomes true after all queued inbound DATA may drain.
	remoteFIN bool
	// writeClosed prevents DATA after local FIN.
	writeClosed bool
	// closed marks RESET or session termination.
	closed bool
	// closeReason is returned by blocked and future operations.
	closeReason error
	// readDeadline bounds blocked Read calls.
	readDeadline time.Time
	// writeDeadline bounds blocked credit and carrier waits.
	writeDeadline time.Time
}

// cfPacketConn implements one connected UDP association over lossy datagram frames.
//
// Example: WriteTo queues one packet or deliberately drops it when the UDP queue is full.
type cfPacketConn struct {
	// session owns carrier lifecycle and association dispatch.
	session *cfSession
	// id is the stable odd association identifier.
	id uint32
	// destination is the single connected UDP peer.
	destination M.Socksaddr
	// access protects deadlines and terminal state.
	access sync.Mutex
	// inbound retains bounded complete packets from the daemon.
	inbound chan []byte
	// closedNotify wakes ReadFrom after association closure.
	closedNotify chan struct{}
	// closeOnce makes local or remote close idempotent.
	closeOnce sync.Once
	// closed marks terminal state under access.
	closed bool
	// readDeadline bounds packet receive waits.
	readDeadline time.Time
	// writeDeadline bounds API compatibility even though sends are lossy.
	writeDeadline time.Time
}

// encode serializes one frame using the Rust mux's five-byte common header.
//
// Example: opcode 5 and stream 1 prepend `[5,0,0,0,1]` to DATA.
func (f cfFrame) encode() []byte {
	encoded := make([]byte, 5+len(f.payload))
	encoded[0] = f.opcode
	binary.BigEndian.PutUint32(encoded[1:5], f.streamID)
	copy(encoded[5:], f.payload)
	return encoded
}

// cfDestinationPayload encodes SOCKS-shaped address metadata without a SOCKS handshake.
//
// Example: domain `example.com:443` becomes type 3, length, bytes, and port.
func cfDestinationPayload(destination M.Socksaddr) ([]byte, error) {
	if !destination.IsValid() || destination.Port == 0 {
		return nil, fmt.Errorf("invalid cf destination: %s", destination.String())
	}
	var payload []byte
	if destination.IsIP() {
		address := destination.Addr.Unmap()
		if address.Is4() {
			payload = make([]byte, 1+4+2)
			payload[0] = 1
			octets := address.As4()
			copy(payload[1:5], octets[:])
		} else {
			payload = make([]byte, 1+16+2)
			payload[0] = 4
			octets := address.As16()
			copy(payload[1:17], octets[:])
		}
	} else {
		domain := destination.Fqdn
		if len(domain) == 0 || len(domain) > 255 || !isASCIIWithoutWhitespace(domain) {
			return nil, fmt.Errorf("invalid cf destination domain")
		}
		payload = make([]byte, 2+len(domain)+2)
		payload[0] = 3
		payload[1] = byte(len(domain))
		copy(payload[2:], domain)
	}
	binary.BigEndian.PutUint16(payload[len(payload)-2:], destination.Port)
	return payload, nil
}

// isASCIIWithoutWhitespace validates protocol domain bytes without DNS resolution.
//
// Example: punycode passes while spaces and non-ASCII Unicode fail closed.
func isASCIIWithoutWhitespace(value string) bool {
	for _, character := range value {
		if character > 127 || character == ' ' || character == '\t' || character == '\r' || character == '\n' {
			return false
		}
	}
	return true
}

// DialContext opens one direct destination TCP stream without HTTP or SOCKS layering.
//
// Example: `tcp, 192.0.2.154:22` becomes one destination-bearing mux OPEN.
func (o *cfOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, N.ErrUnknownNetwork
	}
	o.logger.InfoContext(ctx, "outbound connection to ", destination)
	session, err := o.liveSession(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := session.openStream(ctx, destination)
	if err == nil {
		return stream, nil
	}
	if session.closed.Load() {
		o.dropSession(session)
		replacement, replacementErr := o.liveSession(ctx)
		if replacementErr != nil {
			return nil, replacementErr
		}
		return replacement.openStream(ctx, destination)
	}
	return nil, err
}

// ListenPacket opens one connected UDP association carrying complete packet boundaries.
//
// Example: DNS destination `1.1.1.1:53` becomes DATAGRAM_OPEN with that address.
func (o *cfOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	o.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	session, err := o.liveSession(ctx)
	if err != nil {
		return nil, err
	}
	association, err := session.openAssociation(ctx, destination)
	if err == nil {
		return association, nil
	}
	if session.closed.Load() {
		o.dropSession(session)
		replacement, replacementErr := o.liveSession(ctx)
		if replacementErr != nil {
			return nil, replacementErr
		}
		return replacement.openAssociation(ctx, destination)
	}
	return nil, err
}

// Close terminates the shared carrier and prevents later lazy recreation.
//
// Example: sing-box shutdown wakes every blocked stream operation with net.ErrClosed.
func (o *cfOutbound) Close() error {
	o.sessionAccess.Lock()
	o.closed = true
	session := o.session
	o.session = nil
	o.sessionAccess.Unlock()
	if session != nil {
		session.close(net.ErrClosed)
	}
	return nil
}

// liveSession returns the healthy shared carrier or creates one exactly once.
//
// Example: simultaneous browser connections wait behind one WSS handshake.
func (o *cfOutbound) liveSession(ctx context.Context) (*cfSession, error) {
	o.sessionAccess.Lock()
	defer o.sessionAccess.Unlock()
	if o.closed {
		return nil, net.ErrClosed
	}
	if o.session != nil && !o.session.closed.Load() {
		return o.session, nil
	}
	endpoint, err := o.resolver.endpoint(ctx, false)
	if err != nil {
		return nil, err
	}
	session, err := newCFSession(o.ctx, ctx, o.tag, endpoint, o.physicalDialer)
	if err != nil && o.resolver.fixed == "" {
		endpoint, refreshErr := o.resolver.endpoint(ctx, true)
		if refreshErr != nil {
			return nil, fmt.Errorf("connect cf mux: %v; refresh endpoint: %w", err, refreshErr)
		}
		session, err = newCFSession(o.ctx, ctx, o.tag, endpoint, o.physicalDialer)
	}
	if err != nil {
		return nil, err
	}
	o.session = session
	o.logger.Info("connected shared CF mux carrier")
	return session, nil
}

// dropSession removes one known stale session without disturbing a newer replacement.
//
// Example: crossed stream failures cannot erase a concurrently installed carrier.
func (o *cfOutbound) dropSession(stale *cfSession) {
	o.sessionAccess.Lock()
	if o.session == stale {
		o.session = nil
	}
	o.sessionAccess.Unlock()
}

// newCFSession upgrades WSS, starts carrier tasks, and completes the HELLO exchange.
//
// Example: the first routed connection lazily creates one reusable session.
func newCFSession(ownerCtx context.Context, dialCtx context.Context, outboundTag string, endpoint string, physicalDialer N.Dialer) (*cfSession, error) {
	colo := ""
	websocketDialer := ws.Dialer{
		Timeout: 20 * time.Second,
		NetDial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return physicalDialer.DialContext(ctx, network, M.ParseSocksaddr(address))
		},
		TLSConfig: &stdTLS.Config{MinVersion: stdTLS.VersionTLS12},
		OnHeader: func(key, value []byte) error {
			if strings.EqualFold(string(key), "CF-Ray") {
				colo = cfColoFromRay(string(value))
			}
			return nil
		},
	}
	connection, buffered, _, err := websocketDialer.Dial(dialCtx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("dial CF mux websocket: %w", err)
	}
	if buffered != nil && buffered.Buffered() > 0 {
		connection = &cfBufferedConn{Conn: connection, reader: buffered}
	}
	sessionCtx, cancel := context.WithCancel(ownerCtx)
	session := &cfSession{
		ctx:                     sessionCtx,
		cancel:                  cancel,
		conn:                    connection,
		control:                 make(chan cfControlCommand, cfControlCapacity),
		data:                    make(chan cfDataEvent, cfDataCapacity),
		datagrams:               make(chan cfFrame, cfDatagramCapacity),
		streams:                 make(map[uint32]*cfMuxConn),
		associations:            make(map[uint32]*cfPacketConn),
		remoteReady:             make(chan struct{}),
		sendWindowNotify:        make(chan struct{}, 1),
		receiveConnectionWindow: cfConnectionWindow,
		statusTag:               outboundTag,
		statusColo:              colo,
		statusConnectedAt:       time.Now().UTC().Format(time.RFC3339Nano),
	}
	session.nextID.Store(1)
	go session.writerLoop()
	go session.readerLoop()
	hello := make([]byte, 18)
	binary.BigEndian.PutUint16(hello[0:2], cfMuxVersion)
	binary.BigEndian.PutUint32(hello[2:6], cfStreamWindow)
	binary.BigEndian.PutUint32(hello[6:10], cfConnectionWindow)
	binary.BigEndian.PutUint32(hello[10:14], cfMaximumFrame)
	binary.BigEndian.PutUint32(hello[14:18], cfMaximumStreams)
	if err = session.sendControl(dialCtx, cfFrame{opcode: cfOpHello, payload: hello}, true); err != nil {
		session.close(err)
		return nil, err
	}
	helloCtx, helloCancel := context.WithTimeout(dialCtx, 20*time.Second)
	defer helloCancel()
	select {
	case <-session.remoteReady:
		// Status reporting is observability-only. An unavailable /run bridge must
		// never turn a healthy carrier into a proxy outage.
		_ = session.writeRuntimeStatus(true)
		return session, nil
	case <-session.ctx.Done():
		return nil, session.err()
	case <-helloCtx.Done():
		session.close(helloCtx.Err())
		return nil, fmt.Errorf("wait CF mux HELLO: %w", helloCtx.Err())
	}
}

// writerLoop serializes all WebSocket writes with bounded control priority and byte fairness.
//
// Example: the thirty-third WINDOW_UPDATE cannot starve ready TCP DATA.
func (s *cfSession) writerLoop() {
	flows := make(map[uint32]*cfFlowState)
	var virtualTime uint64
	controlBurst := 0
	datagramSinceData := false
	heartbeat := time.NewTicker(cfHeartbeatInterval)
	defer heartbeat.Stop()
	for {
		for {
			select {
			case event := <-s.data:
				applyCFDataEvent(flows, &virtualTime, event)
			default:
				goto drained
			}
		}
	drained:
		if controlBurst < cfControlBurst {
			select {
			case command := <-s.control:
				if !s.writeControl(command) {
					return
				}
				controlBurst++
				continue
			default:
			}
		}
		if cfHasPendingData(flows) && !datagramSinceData {
			select {
			case frame := <-s.datagrams:
				if err := s.writeFrame(frame); err != nil {
					s.close(err)
					return
				}
				datagramSinceData = true
				controlBurst = 0
				continue
			default:
			}
		}
		if command := popCFData(flows, &virtualTime); command != nil {
			err := s.writeFrame(cfFrame{opcode: cfOpData, streamID: command.streamID, payload: command.payload})
			command.delivered <- err
			close(command.delivered)
			if err != nil {
				s.close(err)
				return
			}
			controlBurst = 0
			datagramSinceData = false
			continue
		}
		select {
		case <-s.ctx.Done():
			return
		case command := <-s.control:
			if !s.writeControl(command) {
				return
			}
			controlBurst++
		case event := <-s.data:
			applyCFDataEvent(flows, &virtualTime, event)
		case frame := <-s.datagrams:
			if err := s.writeFrame(frame); err != nil {
				s.close(err)
				return
			}
			datagramSinceData = true
			controlBurst = 0
		case <-heartbeat.C:
			if err := s.writeWebSocket(ws.OpPing, nil); err != nil {
				s.close(err)
				return
			}
		}
	}
}

// applyCFDataEvent updates fair-flow state without carrier I/O.
//
// Example: an idle stream rejoins no earlier than current global virtual time.
func applyCFDataEvent(flows map[uint32]*cfFlowState, virtualTime *uint64, event cfDataEvent) {
	switch event.kind {
	case cfDataEnqueue:
		flow := flows[event.command.streamID]
		if flow == nil {
			flow = &cfFlowState{virtualFinish: *virtualTime}
			flows[event.command.streamID] = flow
		}
		if !flow.active {
			if flow.virtualFinish < *virtualTime {
				flow.virtualFinish = *virtualTime
			}
			flow.active = true
		}
		if flow.pending != nil {
			event.command.delivered <- fmt.Errorf("duplicate pending CF mux DATA")
			close(event.command.delivered)
			return
		}
		flow.pending = event.command
	case cfDataIdle:
		if flow := flows[event.streamID]; flow != nil && flow.pending == nil {
			flow.active = false
		}
	case cfDataRemove:
		if flow := flows[event.streamID]; flow != nil {
			if flow.pending != nil {
				flow.pending.delivered <- net.ErrClosed
				close(flow.pending.delivered)
			}
			delete(flows, event.streamID)
		}
		close(event.done)
	}
}

// cfHasPendingData reports whether at least one stream is carrier-ready.
//
// Example: ready DATA limits datagram service to one packet before TCP progresses.
func cfHasPendingData(flows map[uint32]*cfFlowState) bool {
	for _, flow := range flows {
		if flow.pending != nil {
			return true
		}
	}
	return false
}

// popCFData selects the least byte-served ready stream deterministically.
//
// Example: 1KiB interactive frames catch up without permanently starving bulk frames.
func popCFData(flows map[uint32]*cfFlowState, virtualTime *uint64) *cfDataCommand {
	var selectedID uint32
	var selected *cfFlowState
	for streamID, flow := range flows {
		if flow.pending == nil {
			continue
		}
		if selected == nil || flow.virtualFinish < selected.virtualFinish || flow.virtualFinish == selected.virtualFinish && streamID < selectedID {
			selectedID = streamID
			selected = flow
		}
	}
	if selected == nil {
		return nil
	}
	command := selected.pending
	selected.pending = nil
	selected.virtualFinish += uint64(len(command.payload))
	if *virtualTime < selected.virtualFinish {
		*virtualTime = selected.virtualFinish
	}
	return command
}

// writeControl hands one control frame to WSS and resolves its optional waiter.
//
// Example: ordered OPEN wakes only after its physical frame write completes.
func (s *cfSession) writeControl(command cfControlCommand) bool {
	err := s.writeFrame(command.frame)
	if command.delivered != nil {
		command.delivered <- err
		close(command.delivered)
	}
	if err != nil {
		s.close(err)
		return false
	}
	return true
}

// writeFrame serializes one logical frame as one binary WebSocket message.
//
// Example: a DATA frame retains its boundary for the Rust decoder.
func (s *cfSession) writeFrame(frame cfFrame) error {
	return s.writeWebSocket(ws.OpBinary, frame.encode())
}

// writeWebSocket serializes all WebSocket writers including pong and heartbeat.
//
// Example: a reader-generated PONG cannot interleave with a DATA frame.
func (s *cfSession) writeWebSocket(opcode ws.OpCode, payload []byte) error {
	s.wsWrite.Lock()
	defer s.wsWrite.Unlock()
	return wsutil.WriteClientMessage(s.conn, opcode, payload)
}

// sendControl queues lifecycle control and optionally waits for carrier handoff.
//
// Example: OPEN uses ordered=true; WINDOW_UPDATE only waits for bounded queue admission.
func (s *cfSession) sendControl(ctx context.Context, frame cfFrame, ordered bool) error {
	command := cfControlCommand{frame: frame}
	if ordered {
		command.delivered = make(chan error, 1)
	}
	select {
	case s.control <- command:
	case <-ctx.Done():
		return ctx.Err()
	case <-s.ctx.Done():
		return s.err()
	}
	if command.delivered == nil {
		return nil
	}
	select {
	case err := <-command.delivered:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-s.ctx.Done():
		return s.err()
	}
}

// readerLoop decodes complete daemon WebSocket messages and dispatches logical state.
//
// Example: RESET closes only its stream while malformed framing closes the carrier.
func (s *cfSession) readerLoop() {
	for {
		header, err := ws.ReadHeader(s.conn)
		if err != nil {
			s.close(err)
			return
		}
		if !header.Fin || header.Masked || header.Length < 0 || header.Length > cfMaximumFrame+64 {
			s.close(fmt.Errorf("invalid CF websocket frame"))
			return
		}
		payload := make([]byte, int(header.Length))
		if _, err = io.ReadFull(s.conn, payload); err != nil {
			s.close(err)
			return
		}
		switch header.OpCode {
		case ws.OpPing:
			if err = s.writeWebSocket(ws.OpPong, payload); err != nil {
				s.close(err)
				return
			}
			continue
		case ws.OpPong:
			continue
		case ws.OpClose:
			s.close(io.EOF)
			return
		case ws.OpBinary:
		default:
			s.close(fmt.Errorf("unexpected CF websocket opcode %d", header.OpCode))
			return
		}
		if len(payload) < 5 {
			s.close(fmt.Errorf("truncated CF mux frame"))
			return
		}
		frame := cfFrame{
			opcode:   payload[0],
			streamID: binary.BigEndian.Uint32(payload[1:5]),
			payload:  payload[5:],
		}
		if err = s.handleFrame(frame); err != nil {
			s.close(err)
			return
		}
	}
}

// handleFrame applies one validated mux frame to session or logical connection state.
//
// Example: DATA charges receive windows before entering the stream byte queue.
func (s *cfSession) handleFrame(frame cfFrame) error {
	if frame.opcode == cfOpHello {
		return s.handleHello(frame)
	}
	select {
	case <-s.remoteReady:
	default:
		return fmt.Errorf("CF mux frame arrived before HELLO")
	}
	switch frame.opcode {
	case cfOpOpenOK:
		if frame.streamID == 0 || len(frame.payload) != 0 {
			return fmt.Errorf("invalid CF OPEN_OK")
		}
		return nil
	case cfOpOpenError:
		if frame.streamID == 0 || len(frame.payload) != 2 {
			return fmt.Errorf("invalid CF OPEN_ERROR")
		}
		stream := s.stream(frame.streamID)
		if stream == nil {
			return nil
		}
		stream.closeRemote(fmt.Errorf("CF daemon target open failed with code %d", binary.BigEndian.Uint16(frame.payload)))
		_ = s.removeStream(context.Background(), frame.streamID)
		return s.sendControl(context.Background(), cfFrame{opcode: cfOpReset, streamID: frame.streamID, payload: frame.payload}, false)
	case cfOpData:
		if frame.streamID == 0 || len(frame.payload) == 0 || len(frame.payload) > cfMaximumFrame {
			return fmt.Errorf("invalid CF DATA")
		}
		stream := s.stream(frame.streamID)
		if stream == nil {
			return fmt.Errorf("unknown CF stream %d", frame.streamID)
		}
		return stream.receive(frame.payload)
	case cfOpFin:
		if frame.streamID == 0 || len(frame.payload) != 0 {
			return fmt.Errorf("invalid CF FIN")
		}
		if stream := s.stream(frame.streamID); stream != nil {
			stream.receiveFIN()
		}
		return nil
	case cfOpReset:
		if frame.streamID == 0 || len(frame.payload) != 2 {
			return fmt.Errorf("invalid CF RESET")
		}
		if stream := s.stream(frame.streamID); stream != nil {
			stream.closeRemote(fmt.Errorf("CF daemon reset code %d", binary.BigEndian.Uint16(frame.payload)))
			return s.removeStream(context.Background(), frame.streamID)
		}
		return nil
	case cfOpWindowUpdate:
		if frame.streamID == 0 || len(frame.payload) != 4 {
			return fmt.Errorf("invalid CF WINDOW_UPDATE")
		}
		increment := binary.BigEndian.Uint32(frame.payload)
		if increment == 0 {
			return fmt.Errorf("zero CF stream window increment")
		}
		return s.updateStreamWindow(frame.streamID, increment)
	case cfOpConnectionWindowUpdate:
		if frame.streamID != 0 || len(frame.payload) != 4 {
			return fmt.Errorf("invalid CF CONNECTION_WINDOW_UPDATE")
		}
		return s.updateConnectionWindow(binary.BigEndian.Uint32(frame.payload))
	case cfOpDatagramOpenOK:
		if frame.streamID == 0 || len(frame.payload) != 0 {
			return fmt.Errorf("invalid CF DATAGRAM_OPEN_OK")
		}
		return nil
	case cfOpDatagramOpenError:
		if frame.streamID == 0 || len(frame.payload) != 2 {
			return fmt.Errorf("invalid CF DATAGRAM_OPEN_ERROR")
		}
		if association := s.association(frame.streamID); association != nil {
			association.closeRemote()
			s.removeAssociation(frame.streamID)
		}
		return nil
	case cfOpDatagram:
		if frame.streamID == 0 || len(frame.payload) == 0 || len(frame.payload) > cfMaximumFrame {
			return fmt.Errorf("invalid CF DATAGRAM")
		}
		if association := s.association(frame.streamID); association != nil {
			packet := append([]byte(nil), frame.payload...)
			select {
			case association.inbound <- packet:
			default:
			}
		}
		return nil
	case cfOpDatagramClose:
		if frame.streamID == 0 || len(frame.payload) != 0 {
			return fmt.Errorf("invalid CF DATAGRAM_CLOSE")
		}
		if association := s.association(frame.streamID); association != nil {
			association.closeRemote()
			s.removeAssociation(frame.streamID)
		}
		return nil
	default:
		return fmt.Errorf("unknown CF mux opcode %d", frame.opcode)
	}
}

// handleHello installs exactly one compatible set of remote flow-control limits.
//
// Example: daemon's 4MiB stream window seeds later logical stream send credit.
func (s *cfSession) handleHello(frame cfFrame) error {
	if frame.streamID != 0 || len(frame.payload) != 18 {
		return fmt.Errorf("invalid CF HELLO")
	}
	version := binary.BigEndian.Uint16(frame.payload[0:2])
	streamWindow := binary.BigEndian.Uint32(frame.payload[2:6])
	connectionWindow := binary.BigEndian.Uint32(frame.payload[6:10])
	maximumFrame := binary.BigEndian.Uint32(frame.payload[10:14])
	maximumStreams := binary.BigEndian.Uint32(frame.payload[14:18])
	if version != cfMuxVersion || streamWindow == 0 || connectionWindow == 0 || maximumFrame == 0 || maximumFrame > streamWindow || maximumStreams == 0 {
		return fmt.Errorf("incompatible CF HELLO")
	}
	installed := false
	s.remoteReadyOnce.Do(func() {
		s.remoteAccess.Lock()
		s.remoteStreamWindow = streamWindow
		s.remoteMaximumFrame = maximumFrame
		s.remoteMaximumStreams = maximumStreams
		s.sendConnectionWindow = connectionWindow
		s.remoteConnectionWindow = connectionWindow
		s.remoteAccess.Unlock()
		close(s.remoteReady)
		installed = true
	})
	if !installed {
		return fmt.Errorf("duplicate CF HELLO")
	}
	return nil
}

// close terminates one carrier and every registered logical connection exactly once.
//
// Example: WSS EOF wakes blocked SSH Read and Write calls immediately.
func (s *cfSession) close(reason error) {
	if reason == nil {
		reason = net.ErrClosed
	}
	if !s.closed.CompareAndSwap(false, true) {
		return
	}
	s.closeErrAccess.Lock()
	s.closeErr = reason
	s.closeErrAccess.Unlock()
	_ = s.writeRuntimeStatus(false)
	s.cancel()
	_ = s.conn.Close()
	s.streamsAccess.Lock()
	streams := make([]*cfMuxConn, 0, len(s.streams))
	for _, stream := range s.streams {
		streams = append(streams, stream)
	}
	associations := make([]*cfPacketConn, 0, len(s.associations))
	for _, association := range s.associations {
		associations = append(associations, association)
	}
	s.streams = make(map[uint32]*cfMuxConn)
	s.associations = make(map[uint32]*cfPacketConn)
	s.streamsAccess.Unlock()
	for _, stream := range streams {
		stream.closeRemote(reason)
	}
	for _, association := range associations {
		association.closeRemote()
	}
	signalCF(s.sendWindowNotify)
}

// err returns the stable terminal carrier reason.
//
// Example: a clean shutdown returns net.ErrClosed instead of nil.
func (s *cfSession) err() error {
	s.closeErrAccess.Lock()
	defer s.closeErrAccess.Unlock()
	if s.closeErr == nil {
		return net.ErrClosed
	}
	return s.closeErr
}

// stream looks up one active TCP stream without holding the map during I/O.
//
// Example: late WINDOW_UPDATE for a removed stream returns nil harmlessly.
func (s *cfSession) stream(streamID uint32) *cfMuxConn {
	s.streamsAccess.RLock()
	stream := s.streams[streamID]
	s.streamsAccess.RUnlock()
	return stream
}

// association looks up one active UDP association.
//
// Example: a packet for an expired association is dropped without closing WSS.
func (s *cfSession) association(associationID uint32) *cfPacketConn {
	s.streamsAccess.RLock()
	association := s.associations[associationID]
	s.streamsAccess.RUnlock()
	return association
}

// allocateID reserves one odd identifier under the peer's concurrency limit.
//
// Example: successive allocations return 1, 3, and 5.
func (s *cfSession) allocateID() (uint32, error) {
	s.remoteAccess.Lock()
	maximumStreams := s.remoteMaximumStreams
	s.remoteAccess.Unlock()
	s.streamsAccess.RLock()
	active := len(s.streams) + len(s.associations)
	s.streamsAccess.RUnlock()
	if maximumStreams == 0 || active >= int(maximumStreams) {
		return 0, fmt.Errorf("CF mux remote stream limit reached")
	}
	identifier := s.nextID.Add(2) - 2
	if identifier == 0 || identifier > ^uint32(0)-2 {
		return 0, fmt.Errorf("CF mux stream identifier exhausted")
	}
	return identifier, nil
}

// openStream registers state, orders destination OPEN, and returns before OPEN_OK.
//
// Example: SSH client bytes can flow while the daemon performs target connect.
func (s *cfSession) openStream(ctx context.Context, destination M.Socksaddr) (*cfMuxConn, error) {
	payload, err := cfDestinationPayload(destination)
	if err != nil {
		return nil, err
	}
	identifier, err := s.allocateID()
	if err != nil {
		return nil, err
	}
	s.remoteAccess.Lock()
	streamWindow := s.remoteStreamWindow
	s.remoteAccess.Unlock()
	stream := &cfMuxConn{
		session:       s,
		id:            identifier,
		destination:   destination,
		inboundNotify: make(chan struct{}, 1),
		sendWindow:    streamWindow,
		receiveWindow: cfStreamWindow,
	}
	s.streamsAccess.Lock()
	s.streams[identifier] = stream
	s.streamsAccess.Unlock()
	if err = s.sendControl(ctx, cfFrame{opcode: cfOpOpen, streamID: identifier, payload: payload}, true); err != nil {
		stream.closeRemote(err)
		_ = s.removeStream(context.Background(), identifier)
		return nil, err
	}
	return stream, nil
}

// openAssociation registers one direct connected UDP destination and orders its OPEN.
//
// Example: a DNS flow returns before DATAGRAM_OPEN_OK so its first packet may queue remotely.
func (s *cfSession) openAssociation(ctx context.Context, destination M.Socksaddr) (*cfPacketConn, error) {
	payload, err := cfDestinationPayload(destination)
	if err != nil {
		return nil, err
	}
	identifier, err := s.allocateID()
	if err != nil {
		return nil, err
	}
	association := &cfPacketConn{
		session:      s,
		id:           identifier,
		destination:  destination,
		inbound:      make(chan []byte, cfDatagramReceiveCapacity),
		closedNotify: make(chan struct{}),
	}
	s.streamsAccess.Lock()
	s.associations[identifier] = association
	s.streamsAccess.Unlock()
	if err = s.sendControl(ctx, cfFrame{opcode: cfOpDatagramOpen, streamID: identifier, payload: payload}, true); err != nil {
		association.closeRemote()
		s.removeAssociation(identifier)
		return nil, err
	}
	return association, nil
}

// removeStream unregisters fair DATA before later RESET and restores discarded connection credit.
//
// Example: rejected early DATA cannot leak aggregate receive window after stream removal.
func (s *cfSession) removeStream(ctx context.Context, streamID uint32) error {
	s.streamsAccess.Lock()
	stream := s.streams[streamID]
	delete(s.streams, streamID)
	s.streamsAccess.Unlock()
	if stream == nil {
		return nil
	}
	done := make(chan struct{})
	select {
	case s.data <- cfDataEvent{kind: cfDataRemove, streamID: streamID, done: done}:
	case <-ctx.Done():
		return ctx.Err()
	case <-s.ctx.Done():
		return s.err()
	}
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	case <-s.ctx.Done():
		return s.err()
	}
	stream.stateAccess.Lock()
	discarded := uint32(stream.inbound.Len())
	stream.inbound.Reset()
	stream.stateAccess.Unlock()
	if discarded == 0 {
		return nil
	}
	s.receiveAccess.Lock()
	if cfConnectionWindow-s.receiveConnectionWindow < discarded {
		s.receiveAccess.Unlock()
		return fmt.Errorf("CF connection receive credit overflow")
	}
	s.receiveConnectionWindow += discarded
	s.receiveConnectionPending += discarded
	increment := s.receiveConnectionPending
	s.receiveConnectionPending = 0
	s.receiveAccess.Unlock()
	return s.sendWindowUpdate(cfOpConnectionWindowUpdate, 0, increment)
}

// removeAssociation forgets one UDP identifier without affecting sibling flows.
//
// Example: remote DATAGRAM_CLOSE releases one association slot immediately.
func (s *cfSession) removeAssociation(associationID uint32) {
	s.streamsAccess.Lock()
	delete(s.associations, associationID)
	s.streamsAccess.Unlock()
}

// updateStreamWindow returns peer-confirmed credit to one active stream.
//
// Example: consuming 64KiB on the daemon wakes a blocked local Write.
func (s *cfSession) updateStreamWindow(streamID uint32, increment uint32) error {
	if increment == 0 {
		return fmt.Errorf("zero CF stream window increment")
	}
	stream := s.stream(streamID)
	if stream == nil {
		return nil
	}
	s.remoteAccess.Lock()
	if s.remoteStreamWindow-stream.sendWindow < increment {
		s.remoteAccess.Unlock()
		return fmt.Errorf("CF stream send window overflow")
	}
	stream.sendWindow += increment
	s.remoteAccess.Unlock()
	signalCF(s.sendWindowNotify)
	return nil
}

// updateConnectionWindow returns peer-confirmed aggregate send credit.
//
// Example: one target write can unblock a different stream sharing the carrier.
func (s *cfSession) updateConnectionWindow(increment uint32) error {
	if increment == 0 {
		return fmt.Errorf("zero CF connection window increment")
	}
	s.remoteAccess.Lock()
	if s.remoteConnectionWindow-s.sendConnectionWindow < increment {
		s.remoteAccess.Unlock()
		return fmt.Errorf("CF connection send window overflow")
	}
	s.sendConnectionWindow += increment
	s.remoteAccess.Unlock()
	signalCF(s.sendWindowNotify)
	return nil
}

// reserveSend atomically charges stream and aggregate credit before DATA is accepted.
//
// Example: zero aggregate credit blocks Write and therefore stops sing-box's next source read.
func (s *cfSession) reserveSend(stream *cfMuxConn, maximum int, deadline time.Time) (int, error) {
	for {
		stream.stateAccess.Lock()
		closed := stream.closed
		reason := stream.closeReason
		writeClosed := stream.writeClosed
		stream.stateAccess.Unlock()
		if closed {
			if reason != nil {
				return 0, reason
			}
			return 0, net.ErrClosed
		}
		if writeClosed {
			return 0, io.ErrClosedPipe
		}
		s.remoteAccess.Lock()
		available := stream.sendWindow
		if s.sendConnectionWindow < available {
			available = s.sendConnectionWindow
		}
		if s.remoteMaximumFrame < available {
			available = s.remoteMaximumFrame
		}
		if uint32(maximum) < available {
			available = uint32(maximum)
		}
		if available > 0 {
			stream.sendWindow -= available
			s.sendConnectionWindow -= available
			s.remoteAccess.Unlock()
			return int(available), nil
		}
		s.remoteAccess.Unlock()
		if err := waitCF(s.ctx, s.sendWindowNotify, deadline); err != nil {
			return 0, err
		}
	}
}

// restoreSend returns locally reserved credit after failed carrier handoff.
//
// Example: WSS closure before DATA write cannot permanently shrink either window.
func (s *cfSession) restoreSend(stream *cfMuxConn, amount uint32) {
	s.remoteAccess.Lock()
	stream.sendWindow += amount
	s.sendConnectionWindow += amount
	s.remoteAccess.Unlock()
	signalCF(s.sendWindowNotify)
}

// sendWindowUpdate encodes one positive four-byte receive-credit increment.
//
// Example: stream 1 consumption emits WINDOW_UPDATE with identifier 1.
func (s *cfSession) sendWindowUpdate(opcode byte, streamID uint32, increment uint32) error {
	if increment == 0 {
		return nil
	}
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, increment)
	return s.sendControl(context.Background(), cfFrame{opcode: opcode, streamID: streamID, payload: payload}, false)
}

// receive charges local receive windows before appending DATA to the stream queue.
//
// Example: a stalled SSH reader retains at most its advertised stream and connection credit.
func (c *cfMuxConn) receive(payload []byte) error {
	amount := uint32(len(payload))
	c.stateAccess.Lock()
	if c.closed {
		c.stateAccess.Unlock()
		return net.ErrClosed
	}
	c.session.receiveAccess.Lock()
	if amount > c.receiveWindow || amount > c.session.receiveConnectionWindow {
		c.session.receiveAccess.Unlock()
		c.stateAccess.Unlock()
		return fmt.Errorf("CF receive window exceeded")
	}
	c.receiveWindow -= amount
	c.session.receiveConnectionWindow -= amount
	_, _ = c.inbound.Write(payload)
	c.session.receiveAccess.Unlock()
	c.stateAccess.Unlock()
	signalCF(c.inboundNotify)
	return nil
}

// receiveFIN marks remote EOF while allowing already queued DATA to drain.
//
// Example: Read returns remaining bytes before its final io.EOF.
func (c *cfMuxConn) receiveFIN() {
	c.stateAccess.Lock()
	c.remoteFIN = true
	c.stateAccess.Unlock()
	signalCF(c.inboundNotify)
}

// closeRemote terminates one logical stream without emitting another RESET.
//
// Example: daemon RESET wakes blocked local reads with its stable reason.
func (c *cfMuxConn) closeRemote(reason error) {
	c.stateAccess.Lock()
	if !c.closed {
		c.closed = true
		c.closeReason = reason
	}
	c.stateAccess.Unlock()
	signalCF(c.inboundNotify)
	signalCF(c.session.sendWindowNotify)
}

// Read drains queued DATA and returns receive credit only after local consumption.
//
// Example: reading 32KiB can contribute to a later 64KiB WINDOW_UPDATE.
func (c *cfMuxConn) Read(payload []byte) (int, error) {
	for {
		c.stateAccess.Lock()
		if c.inbound.Len() > 0 {
			read, _ := c.inbound.Read(payload)
			amount := uint32(read)
			c.receiveWindow += amount
			c.receivePending += amount
			streamIncrement := uint32(0)
			if c.receivePending >= cfWindowThreshold {
				streamIncrement = c.receivePending
				c.receivePending = 0
			}
			c.session.receiveAccess.Lock()
			c.session.receiveConnectionWindow += amount
			c.session.receiveConnectionPending += amount
			connectionIncrement := uint32(0)
			if c.session.receiveConnectionPending >= cfWindowThreshold {
				connectionIncrement = c.session.receiveConnectionPending
				c.session.receiveConnectionPending = 0
			}
			c.session.receiveAccess.Unlock()
			c.stateAccess.Unlock()
			if streamIncrement > 0 {
				_ = c.session.sendWindowUpdate(cfOpWindowUpdate, c.id, streamIncrement)
			}
			if connectionIncrement > 0 {
				_ = c.session.sendWindowUpdate(cfOpConnectionWindowUpdate, 0, connectionIncrement)
			}
			return read, nil
		}
		if c.remoteFIN {
			c.stateAccess.Unlock()
			return 0, io.EOF
		}
		if c.closed {
			reason := c.closeReason
			c.stateAccess.Unlock()
			if reason == nil {
				reason = net.ErrClosed
			}
			return 0, reason
		}
		deadline := c.readDeadline
		c.stateAccess.Unlock()
		if err := waitCF(c.session.ctx, c.inboundNotify, deadline); err != nil {
			return 0, err
		}
	}
}

// Write chunks DATA by negotiated frame and window limits with byte-fair carrier service.
//
// Example: a bulk transfer cannot queue more than one unhanded frame for this stream.
func (c *cfMuxConn) Write(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	written := 0
	for written < len(payload) {
		c.stateAccess.Lock()
		deadline := c.writeDeadline
		c.stateAccess.Unlock()
		amount, err := c.session.reserveSend(c, len(payload)-written, deadline)
		if err != nil {
			return written, err
		}
		chunk := append([]byte(nil), payload[written:written+amount]...)
		command := &cfDataCommand{streamID: c.id, payload: chunk, delivered: make(chan error, 1)}
		select {
		case c.session.data <- cfDataEvent{kind: cfDataEnqueue, command: command}:
		case <-c.session.ctx.Done():
			c.session.restoreSend(c, uint32(amount))
			return written, c.session.err()
		}
		select {
		case err = <-command.delivered:
		case <-c.session.ctx.Done():
			err = c.session.err()
		}
		if err != nil {
			c.session.restoreSend(c, uint32(amount))
			return written, err
		}
		written += amount
	}
	select {
	case c.session.data <- cfDataEvent{kind: cfDataIdle, streamID: c.id}:
	case <-c.session.ctx.Done():
	}
	return written, nil
}

// CloseWrite sends one ordered FIN after all earlier DATA from this stream.
//
// Example: SSH channel EOF preserves reverse-direction replies.
func (c *cfMuxConn) CloseWrite() error {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	c.stateAccess.Lock()
	if c.closed || c.writeClosed {
		c.stateAccess.Unlock()
		return nil
	}
	c.writeClosed = true
	c.stateAccess.Unlock()
	return c.session.sendControl(context.Background(), cfFrame{opcode: cfOpFin, streamID: c.id}, true)
}

// CloseRead aborts buffered local receive data by resetting the complete stream.
//
// Example: an application abandoning replies releases daemon and connection credit.
func (c *cfMuxConn) CloseRead() error { return c.Close() }

// Close resets one stream, cancels pending DATA, and preserves sibling connections.
//
// Example: one failed SSH connection does not close the shared WSS.
func (c *cfMuxConn) Close() error {
	c.writeAccess.Lock()
	c.stateAccess.Lock()
	alreadyClosed := c.closed
	if !alreadyClosed {
		c.closed = true
		c.closeReason = net.ErrClosed
	}
	c.stateAccess.Unlock()
	if alreadyClosed {
		c.writeAccess.Unlock()
		return nil
	}
	err := c.session.removeStream(context.Background(), c.id)
	if err == nil && !c.session.closed.Load() {
		code := []byte{0, 1}
		err = c.session.sendControl(context.Background(), cfFrame{opcode: cfOpReset, streamID: c.id, payload: code}, false)
	}
	c.writeAccess.Unlock()
	signalCF(c.inboundNotify)
	return err
}

// LocalAddr returns a standard unspecified TCP address for protocol reply encoders.
//
// Example: a SOCKS inbound can encode `0.0.0.0:0` after opening this mux stream.
func (c *cfMuxConn) LocalAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4zero} }

// RemoteAddr returns the original routed destination.
//
// Example: SSH displays `192.0.2.154:22`.
func (c *cfMuxConn) RemoteAddr() net.Addr {
	return cfRemoteAddr{network: "tcp", address: c.destination.String()}
}

// SetDeadline updates both logical stream deadlines and wakes current waiters.
//
// Example: a past deadline makes the next blocked Read or Write time out.
func (c *cfMuxConn) SetDeadline(deadline time.Time) error {
	c.stateAccess.Lock()
	c.readDeadline = deadline
	c.writeDeadline = deadline
	c.stateAccess.Unlock()
	signalCF(c.inboundNotify)
	signalCF(c.session.sendWindowNotify)
	return nil
}

// SetReadDeadline updates the logical read deadline without touching the shared WSS.
//
// Example: one DNS-over-TCP timeout cannot alter sibling streams.
func (c *cfMuxConn) SetReadDeadline(deadline time.Time) error {
	c.stateAccess.Lock()
	c.readDeadline = deadline
	c.stateAccess.Unlock()
	signalCF(c.inboundNotify)
	return nil
}

// SetWriteDeadline updates the logical send-window wait deadline.
//
// Example: a stalled target eventually returns os.ErrDeadlineExceeded to its caller.
func (c *cfMuxConn) SetWriteDeadline(deadline time.Time) error {
	c.stateAccess.Lock()
	c.writeDeadline = deadline
	c.stateAccess.Unlock()
	signalCF(c.session.sendWindowNotify)
	return nil
}

// ReadFrom receives one complete datagram and reports the connected remote destination.
//
// Example: a daemon DNS reply is returned as one packet from `1.1.1.1:53`.
func (c *cfPacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	for {
		c.access.Lock()
		closed := c.closed
		deadline := c.readDeadline
		c.access.Unlock()
		if closed {
			return 0, nil, net.ErrClosed
		}
		var timer <-chan time.Time
		var deadlineTimer *time.Timer
		if !deadline.IsZero() {
			duration := time.Until(deadline)
			if duration <= 0 {
				return 0, nil, os.ErrDeadlineExceeded
			}
			deadlineTimer = time.NewTimer(duration)
			timer = deadlineTimer.C
		}
		select {
		case packet := <-c.inbound:
			if deadlineTimer != nil {
				deadlineTimer.Stop()
			}
			if len(packet) > len(payload) {
				copy(payload, packet[:len(payload)])
				return len(payload), cfRemoteAddr{network: "udp", address: c.destination.String()}, io.ErrShortBuffer
			}
			copy(payload, packet)
			return len(packet), cfRemoteAddr{network: "udp", address: c.destination.String()}, nil
		case <-c.closedNotify:
			if deadlineTimer != nil {
				deadlineTimer.Stop()
			}
			return 0, nil, net.ErrClosed
		case <-c.session.ctx.Done():
			if deadlineTimer != nil {
				deadlineTimer.Stop()
			}
			return 0, nil, c.session.err()
		case <-timer:
			return 0, nil, os.ErrDeadlineExceeded
		}
	}
}

// WriteTo sends one complete connected datagram without blocking TCP control traffic.
//
// Example: a full UDP carrier queue deliberately drops one packet and reports it consumed.
func (c *cfPacketConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	if len(payload) == 0 || len(payload) > cfMaximumFrame {
		return 0, fmt.Errorf("invalid CF datagram length %d", len(payload))
	}
	c.access.Lock()
	closed := c.closed
	deadline := c.writeDeadline
	c.access.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	frame := cfFrame{opcode: cfOpDatagram, streamID: c.id, payload: append([]byte(nil), payload...)}
	select {
	case c.session.datagrams <- frame:
	default:
		// UDP has no backpressure contract. Dropping here prevents packet bursts from
		// consuming the bounded control path or delaying interactive TCP streams.
	}
	return len(payload), nil
}

// Close unregisters this UDP association and emits one best-effort DATAGRAM_CLOSE.
//
// Example: closing DNS state immediately frees one remote mux identifier.
func (c *cfPacketConn) Close() error {
	first := false
	c.closeOnce.Do(func() {
		first = true
		c.access.Lock()
		c.closed = true
		c.access.Unlock()
		close(c.closedNotify)
		c.session.removeAssociation(c.id)
	})
	if !first || c.session.closed.Load() {
		return nil
	}
	return c.session.sendControl(context.Background(), cfFrame{opcode: cfOpDatagramClose, streamID: c.id}, false)
}

// closeRemote terminates an association without echoing another close frame.
//
// Example: daemon DATAGRAM_CLOSE wakes a blocked local ReadFrom.
func (c *cfPacketConn) closeRemote() {
	c.closeOnce.Do(func() {
		c.access.Lock()
		c.closed = true
		c.access.Unlock()
		close(c.closedNotify)
	})
}

// LocalAddr returns a standard unspecified UDP address for PacketConn consumers.
//
// Example: a SOCKS UDP reply can encode `0.0.0.0:0` without a custom address type.
func (c *cfPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero}
}

// SetDeadline updates packet read and write deadlines together.
//
// Example: a past deadline makes the next blocked ReadFrom time out.
func (c *cfPacketConn) SetDeadline(deadline time.Time) error {
	c.access.Lock()
	c.readDeadline = deadline
	c.writeDeadline = deadline
	c.access.Unlock()
	return nil
}

// SetReadDeadline updates only the next UDP receive wait deadline.
//
// Example: a 2-second DNS timeout does not close the shared WSS.
func (c *cfPacketConn) SetReadDeadline(deadline time.Time) error {
	c.access.Lock()
	c.readDeadline = deadline
	c.access.Unlock()
	return nil
}

// SetWriteDeadline rejects sends after the configured local deadline.
//
// Example: an expired deadline returns os.ErrDeadlineExceeded before queueing.
func (c *cfPacketConn) SetWriteDeadline(deadline time.Time) error {
	c.access.Lock()
	c.writeDeadline = deadline
	c.access.Unlock()
	return nil
}

// waitCF blocks on one coalesced wakeup, context cancellation, or deadline.
//
// Example: zero window waits until WINDOW_UPDATE signals the notification channel.
func waitCF(ctx context.Context, notify <-chan struct{}, deadline time.Time) error {
	if deadline.IsZero() {
		select {
		case <-notify:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	duration := time.Until(deadline)
	if duration <= 0 {
		return os.ErrDeadlineExceeded
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-notify:
		return nil
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return os.ErrDeadlineExceeded
		}
		return ctx.Err()
	case <-timer.C:
		return os.ErrDeadlineExceeded
	}
}

// signalCF publishes one coalesced wakeup without blocking protocol readers.
//
// Example: ten WINDOW_UPDATE frames need only one pending scheduler wakeup.
func signalCF(notify chan<- struct{}) {
	select {
	case notify <- struct{}{}:
	default:
	}
}
