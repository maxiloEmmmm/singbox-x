package uu

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const runtimeDir = "/run/sboxctl/uu-outbound"

// statusView describes one outbound for the sboxctl panel.
type statusView struct {
	// loginView supplies the shared login state and optional QR image.
	loginView
	// Connection is idle, selecting_device, connecting, connected, or error.
	Connection string `json:"connection"`
	// ConnectionError is the last sanitized carrier failure.
	ConnectionError string `json:"connection_error,omitempty"`
}

// controlPath determines the per-tag socket, e.g. static-uu-home -> an opaque socket filename.
func controlPath(tag string) string {
	dir := os.Getenv("SBOXCTL_UU_RUNTIME_DIR")
	if dir == "" {
		dir = runtimeDir
	}
	digest := sha256.Sum256([]byte(tag))
	return filepath.Join(dir, hex.EncodeToString(digest[:12])+".sock")
}

// startControl publishes an owner-only Unix API, e.g. GET /status -> auth plus carrier status.
func (o *Outbound) startControl() (*http.Server, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", o.handleStatus)
	mux.HandleFunc("POST /login", o.handleLogin)
	mux.HandleFunc("GET /devices", o.handleDevices)
	return startControlSocket(o.ctx, controlPath(o.Tag()), mux)
}

// startControlSocket opens an owner-only local endpoint, e.g. uu-host -> one host socket.
func startControlSocket(ctx context.Context, path string, handler http.Handler) (*http.Server, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("UU control directory must be private")
	}
	if info, err = os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("UU control path is not a socket")
		}
		probe, dialErr := net.DialTimeout("unix", path, time.Second)
		if dialErr == nil {
			probe.Close()
			return nil, errors.New("UU control socket is already in use")
		}
		if errors.Is(dialErr, syscall.ECONNREFUSED) {
			if err = os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(path, 0o600); err != nil {
		listener.Close()
		return nil, err
	}
	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: 3 * time.Second, WriteTimeout: 15 * time.Second, MaxHeaderBytes: 8192,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	go func() { _ = server.Serve(listener) }()
	return server, nil
}

// handleStatus returns both states, e.g. authenticated with no configured device -> selecting_device.
func (o *Outbound) handleStatus(w http.ResponseWriter, _ *http.Request) {
	writeControlJSON(w, http.StatusOK, o.status())
}

// handleLogin starts or resumes one QR prompt, e.g. repeated clicks return the same login.
func (o *Outbound) handleLogin(w http.ResponseWriter, _ *http.Request) {
	o.account.start(o.ctx, o.cloud)
	writeControlJSON(w, http.StatusAccepted, o.status())
}

// handleDevices returns the visible device list, e.g. an expired account -> HTTP 401.
func (o *Outbound) handleDevices(w http.ResponseWriter, req *http.Request) {
	serveAccountDevices(w, req, o.account, o.cloud)
}

// serveAccountDevices returns the selected account's inventory, e.g. account B -> B's devices.
func serveAccountDevices(w http.ResponseWriter, req *http.Request, profile *account, cloud cloudClient) {
	creds, err := profile.current()
	if err != nil {
		writeControlJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(req.Context(), 10*time.Second)
	defer cancel()
	list, err := cloud.devices(ctx, creds)
	if errors.Is(err, errLoginExpired) {
		profile.expire(creds.Token)
		writeControlJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	if err != nil {
		writeControlJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeControlJSON(w, http.StatusOK, map[string]any{"devices": list})
}

// status returns a snapshot, e.g. a live carrier -> connected.
func (o *Outbound) status() statusView {
	o.mu.Lock()
	defer o.mu.Unlock()
	view := statusView{loginView: o.account.status(), Connection: "idle"}
	switch {
	case o.options.DeviceID == "":
		view.Connection = "selecting_device"
	case o.session != nil && o.session.ctx.Err() == nil:
		view.Connection = "connected"
	case o.attempt != nil:
		view.Connection = "connecting"
	case o.lastError != nil:
		view.Connection, view.ConnectionError = "error", o.lastError.Error()
	}
	return view
}

// writeControlJSON sends a local API response with caching disabled for QR credentials.
func writeControlJSON(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(value)
}
