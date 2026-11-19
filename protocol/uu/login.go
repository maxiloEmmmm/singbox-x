package uu

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/uuid/v5"
	qrcode "github.com/skip2/go-qrcode"
)

// accounts shares one login and credential file across UU outbounds of the same process.
var accounts sync.Map

// loginView is the subset of the account state the panel may see.
type loginView struct {
	// Auth is the sign-in state, independent of the forwarding connection.
	Auth string `json:"auth"`
	// QR is an ephemeral PNG data URL, returned only during login.
	QR string `json:"qr,omitempty"`
	// AuthError is a sanitized failure description.
	AuthError string `json:"auth_error,omitempty"`
}

// account owns serialized QR login and the credentials shared by local UU outbounds.
type account struct {
	// path locates the private credential record.
	path string
	// nameSuffix distinguishes the local publisher identity from the controller if both use one account.
	nameSuffix string
	// mu serializes login state and credential replacement.
	mu sync.Mutex
	// creds is the current or provisional device identity.
	creds credentials
	// view is the currently visible login state.
	view loginView
	// busy marks the sole outstanding QR login operation.
	busy bool
}

// accountFor returns the local profile, e.g. multiple outbounds share credentials.json.
func accountFor(path string) *account {
	if current, ok := accounts.Load(path); ok {
		return current.(*account)
	}
	nameSuffix := ""
	if filepath.Base(path) == "host-credentials.json" {
		nameSuffix = " (UU Host)"
	}
	current := &account{path: path, nameSuffix: nameSuffix, view: loginView{Auth: "unsigned"}}
	if saved, err := loadCredentials(path); err == nil {
		current.creds = saved
		if saved.signedIn() {
			current.view.Auth = "authenticated"
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		current.view = loginView{Auth: "error", AuthError: "无法读取 UU 凭据"}
	}
	value, _ := accounts.LoadOrStore(path, current)
	return value.(*account)
}

// status returns a copy for the private local API, e.g. Auth "scanned".
func (a *account) status() loginView {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.view
}

// current returns valid local credentials, e.g. expired login -> an error.
func (a *account) current() (credentials, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.view.Auth == "expired" {
		return credentials{}, errLoginExpired
	}
	if !a.creds.signedIn() {
		return credentials{}, errors.New("请先完成 UU 扫码登录")
	}
	return a.creds, nil
}

// expire marks only the rejected credential, e.g. a late response cannot expire a new login.
func (a *account) expire(token string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.busy && a.creds.Token == token {
		a.view = loginView{Auth: "expired"}
	}
}

// start begins one login for the whole profile, e.g. a second click returns the existing QR state.
func (a *account) start(ctx context.Context, cloud cloudClient) loginView {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.busy {
		return a.view
	}
	a.busy = true
	a.view = loginView{Auth: "starting"}
	go a.login(ctx, cloud, a.creds)
	return a.view
}

// login publishes a QR and persists the result, e.g. a confirmed scan -> authenticated.
func (a *account) login(parent context.Context, cloud cloudClient, saved credentials) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
	defer cancel()
	result, err := a.scan(ctx, cloud, saved)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.busy = false
	switch {
	case err == nil:
		a.creds = result
		a.view = loginView{Auth: "authenticated"}
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, errQRExpired):
		a.view = loginView{Auth: "qr_expired"}
	case errors.Is(err, context.Canceled):
		a.view = loginView{Auth: "unsigned"}
	default:
		a.view = loginView{Auth: "error", AuthError: err.Error()}
	}
}

var errQRExpired = errors.New("UU 二维码已失效")

// scan implements the upstream QR sequence, e.g. status 2 -> wait for approval on the phone.
func (a *account) scan(ctx context.Context, cloud cloudClient, saved credentials) (credentials, error) {
	provisional, err := prepareDevice(ctx, cloud, a.path, a.nameSuffix, saved)
	if err != nil {
		return credentials{}, err
	}
	a.mu.Lock()
	a.creds = provisional
	a.mu.Unlock()
	anonymous := provisional
	anonymous.UserID, anonymous.Token, anonymous.CSRF = "", "", ""
	var qr struct {
		URL    string `json:"qrcode_jump_url"`
		Ticket string `json:"status_query_ticket"`
		Token  string `json:"token"`
	}
	if _, err = cloud.request(ctx, anonymous, http.MethodPost, "/api/v1/qrcode/gen/login", nil, &qr); err != nil {
		return credentials{}, err
	}
	if qr.Ticket == "" {
		qr.Ticket = qr.Token
	}
	if qr.URL == "" || qr.Ticket == "" {
		return credentials{}, errors.New("UU 云端没有返回二维码")
	}
	png, err := qrcode.Encode(qr.URL, qrcode.Medium, 256)
	if err != nil {
		return credentials{}, errors.New("无法生成 UU 二维码")
	}
	a.mu.Lock()
	a.view = loginView{Auth: "waiting_scan", QR: "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)}
	a.mu.Unlock()
	last := 1
	for {
		query := map[string]any{"token": qr.Ticket, "qrcode_jump_url": qr.URL, "login_status": last}
		var answer struct {
			Status int `json:"status"`
		}
		// A long-poll timeout says nothing about the QR's validity. Keep using the
		// same ticket until the service reports expiry or the login deadline ends.
		poll, cancel := context.WithTimeout(ctx, 64*time.Second)
		code, err := cloud.request(poll, anonymous, http.MethodPost, "/api/v1/qrcode/login/status", query, &answer)
		cancel()
		if ctx.Err() != nil {
			return credentials{}, ctx.Err()
		}
		if code == 1190 || (err == nil && (answer.Status == 0 || answer.Status == 3)) {
			return credentials{}, errQRExpired
		}
		if errors.Is(err, context.DeadlineExceeded) {
			continue
		}
		if err != nil {
			return credentials{}, err
		}
		switch answer.Status {
		case 1:
			last = 1
		case 2:
			last = 2
			a.mu.Lock()
			a.view.Auth = "scanned"
			a.mu.Unlock()
		case 4:
			return exchangeLogin(ctx, cloud, a.path, provisional, anonymous, qr.Ticket, qr.URL)
		default:
			return credentials{}, errors.New("未知的 UU 扫码状态")
		}
		// The endpoint normally long-polls. A short delay prevents a tight retry loop
		// if a cached or intermediary response returns immediately.
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return credentials{}, ctx.Err()
		case <-timer.C:
		}
	}
}

// prepareDevice reuses the local instance identity, e.g. a missing DeviceID -> one registration.
func prepareDevice(ctx context.Context, cloud cloudClient, path, nameSuffix string, saved credentials) (credentials, error) {
	if saved.ClientID == "" || saved.SystemID == "" || saved.MachineGUID == "" {
		client, err := uuid.NewV4()
		if err != nil {
			return credentials{}, err
		}
		system, err := uuid.NewV4()
		if err != nil {
			return credentials{}, err
		}
		machine, err := uuid.NewV4()
		if err != nil {
			return credentials{}, err
		}
		saved = credentials{ClientID: client.String(), SystemID: strings.ToUpper(system.String()), MachineGUID: machine.String()}
		if err = saveCredentials(path, saved); err != nil {
			return credentials{}, err
		}
	}
	if saved.DeviceID != "" {
		return saved, nil
	}
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "sing-box"
	}
	body := map[string]any{
		"name": hostname + nameSuffix, "client_id": saved.ClientID, "system_id": saved.SystemID, "machine_guid": saved.MachineGUID,
		"os": runtime.GOOS, "base_board": "Unknown", "cpu": runtime.GOARCH, "video": []string{"Unknown"}, "mac": "", "memory": 0,
		"screen": "1920x1080",
	}
	var reply struct {
		ID string `json:"device_id"`
	}
	if _, err := cloud.request(ctx, saved, http.MethodPost, "/api/v1/device/windows/init", body, &reply); err != nil {
		return credentials{}, err
	}
	if !validDeviceID(reply.ID) {
		return credentials{}, errors.New("UU 云端没有返回本机设备 ID")
	}
	saved.DeviceID = reply.ID
	return saved, saveCredentials(path, saved)
}

// exchangeLogin finalizes a confirmed scan, e.g. a token with its CSRF claim -> a private config.
func exchangeLogin(ctx context.Context, cloud cloudClient, path string, saved, anonymous credentials, ticket, qrURL string) (credentials, error) {
	var reply struct {
		Token  string `json:"token"`
		UserID string `json:"user_id"`
	}
	body := map[string]string{"token": ticket, "qrcode_jump_url": qrURL}
	if _, err := cloud.request(ctx, anonymous, http.MethodPost, "/api/v1/login/by_qrcode", body, &reply); err != nil {
		return credentials{}, err
	}
	saved.Token, saved.UserID, saved.CSRF = reply.Token, reply.UserID, csrfClaim(reply.Token)
	if !saved.signedIn() {
		return credentials{}, errors.New("UU 云端没有返回完整登录凭据")
	}
	return saved, saveCredentials(path, saved)
}

// csrfClaim reads the signed-in token's JSON claim, e.g. a malformed token -> empty.
func csrfClaim(token string) string {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return ""
	}
	var claims struct {
		CSRF string `json:"csrf"`
	}
	if json.Unmarshal(raw, &claims) != nil {
		return ""
	}
	return claims.CSRF
}

// loadCredentials reads an owner-only record, e.g. mode 0644 -> refused.
func loadCredentials(path string) (credentials, error) {
	var result credentials
	info, err := os.Lstat(path)
	if err != nil {
		return result, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > 64*1024 {
		return result, errors.New("UU 凭据文件权限或大小不正确")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(raw, &result)
	return result, err
}

// saveCredentials replaces the owner-only record atomically, e.g. a confirmed scan survives restart.
func saveCredentials(path string, value credentials) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return errors.New("无法创建 UU 凭据目录")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("UU 凭据目录必须仅当前用户可访问")
	}
	file, err := os.CreateTemp(dir, ".credentials-*")
	if err != nil {
		return errors.New("无法创建 UU 凭据文件")
	}
	defer os.Remove(file.Name())
	err = json.NewEncoder(file).Encode(value)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil || os.Rename(file.Name(), path) != nil {
		return errors.New("无法保存 UU 凭据")
	}
	return nil
}
