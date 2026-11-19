// Package uu implements the UU Remote port-mapping controller.
package uu

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	cloudURL = "https://api.nrd.nie.163.com"
	// This is the public client signing identifier from uu-remote-linux v0.2.61.
	clientSigningKey = "alWiSzXZTLu3WfFnw13uBru3"
	clientVersion    = "4.45.0.4318"
	viewerVersion    = "4.42.0"
)

var errLoginExpired = errors.New("UU 登录已过期")

// credentials is the private local account and installation record.
type credentials struct {
	// ClientID and SystemID are stable installation identifiers.
	ClientID string `json:"client_id"`
	// SystemID is the uppercase system UUID.
	SystemID string `json:"system_id"`
	// MachineGUID identifies this local installation.
	MachineGUID string `json:"machine_guid"`
	// DeviceID is allocated by the cloud for this controller.
	DeviceID string `json:"device_id"`
	// UserID identifies the authenticated account.
	UserID string `json:"user_id,omitempty"`
	// Token authorizes account requests.
	Token string `json:"token,omitempty"`
	// CSRF is the authenticated token's CSRF claim.
	CSRF string `json:"csrf,omitempty"`
}

// signedIn checks for complete credentials, e.g. a provisional device -> false.
func (c credentials) signedIn() bool {
	return c.UserID != "" && c.Token != "" && c.CSRF != "" && c.DeviceID != "" && c.ClientID != "" && c.SystemID != ""
}

// cloudClient executes authenticated UU HTTPS calls over the outbound's dialer.
type cloudClient struct {
	// http is shared with the WSS dialer to use the same network path.
	http *http.Client
	// base is the cloud origin.
	base string
}

// room contains the cloud-assigned information for opening a controller connection.
type room struct {
	// Token is the private room ticket.
	Token string `json:"token"`
	// Signaling is the ordered list of room WebSocket origins.
	Signaling []string `json:"signaling_list"`
	// TimeoutMS is the server's suggested WSS dial timeout.
	TimeoutMS int `json:"ws_connect_timeout_ms"`
}

// device is the part of a cloud device entry exposed to the authenticated panel.
type device struct {
	// ID is the value saved in the outbound.
	ID string `json:"device_id"`
	// Name is the UI label supplied by the cloud.
	Name string `json:"name"`
	// Alias is the device name shown by the account's device list.
	Alias string `json:"alias,omitempty"`
	// DeviceName is an alternate label used by some cloud entries.
	DeviceName string `json:"device_name,omitempty"`
}

// request signs one request and decodes its data, e.g. GET /api/v1/device/list -> device inventory.
func (c cloudClient) request(ctx context.Context, creds credentials, method, path string, body, output any) (int, error) {
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			return 0, errors.New("无法编码 UU 请求")
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(payload))
	if err != nil {
		return 0, errors.New("无法创建 UU 请求")
	}
	req.Header = signedHeaders(creds, method, path, payload, time.Now().Unix())
	reply, err := c.http.Do(req)
	if err != nil {
		// HTTP errors can include request URLs. Return a stable diagnostic without credentials.
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		var networkError net.Error
		var dnsError *net.DNSError
		switch {
		case errors.As(err, &dnsError):
			return 0, errors.New("UU 云端 DNS 解析失败")
		case errors.As(err, &networkError) && networkError.Timeout():
			return 0, errors.New("UU 云端网络请求超时")
		}
		return 0, errors.New("UU 云端请求失败")
	}
	defer reply.Body.Close()
	var envelope struct {
		Code *int            `json:"code"`
		Data json.RawMessage `json:"data"`
	}
	if err = json.NewDecoder(io.LimitReader(reply.Body, 2<<20)).Decode(&envelope); err != nil || envelope.Code == nil {
		return 0, fmt.Errorf("UU 云端响应无效（HTTP %d）", reply.StatusCode)
	}
	code := *envelope.Code
	switch {
	case code == 1120 || (reply.StatusCode == http.StatusUnauthorized && creds.Token != ""):
		return code, errLoginExpired
	case code != 0 || reply.StatusCode != http.StatusOK:
		return code, fmt.Errorf("UU 云端请求被拒绝（HTTP %d，UU %d）", reply.StatusCode, code)
	case output != nil && json.Unmarshal(envelope.Data, output) != nil:
		return code, errors.New("UU 云端数据无效")
	default:
		return code, nil
	}
}

// signedHeaders constructs the upstream viewer's signed headers, e.g. an unsigned account includes only device identity.
func signedHeaders(creds credentials, method, path string, payload []byte, now int64) http.Header {
	params := map[string]string{
		"x-param-plat": "1", "x-param-vn": clientVersion, "x-param-vc": "4318",
		"x-param-pkgn": "com.netease.gameviewer", "x-param-chn": "gwqd",
		"x-param-lang": "zh-CN", "x-param-cnt": "CN", "x-param-ts": strconv.FormatInt(now, 10),
	}
	for key, value := range map[string]string{
		"x-param-client-id": creds.ClientID, "x-param-device-id": creds.DeviceID,
		"x-param-system-id": creds.SystemID, "x-param-user-id": creds.UserID,
	} {
		if value != "" {
			params[key] = value
		}
	}
	header := http.Header{
		"Accept": {"application/json"}, "Content-Type": {"application/json"},
		"User-Agent": {"UURemote/4.45.0 (Windows NT 10.0; Win64; x64)"},
	}
	if creds.Token != "" {
		header.Set("Authorization", "Bearer "+creds.Token)
		header.Set("Cookie", "nrd_access_token="+creds.Token+"; nrd_csrf_access_token="+creds.CSRF)
		header.Set("X-CSRF-TOKEN", creds.CSRF)
	}
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		header.Set(key, params[key])
		parts = append(parts, key+"="+params[key])
	}
	mac := hmac.New(sha256.New, []byte(clientSigningKey))
	mac.Write([]byte(method + path + strings.Join(parts, "&")))
	mac.Write(payload)
	header.Set("X-Param-Sign", hex.EncodeToString(mac.Sum(nil)))
	return header
}

// join opens a port-map room for a selected device, e.g. "185-device" -> a room ticket.
func (c cloudClient) join(ctx context.Context, creds credentials, deviceID string) (room, error) {
	var target room
	_, err := c.request(ctx, creds, http.MethodPost, "/api/v1/room/join/by_device/"+url.PathEscape(deviceID),
		struct {
			Force bool `json:"force_join"`
		}{}, &target)
	if err == nil && (target.Token == "" || len(target.Signaling) == 0) {
		err = errors.New("UU 云端没有返回可用房间")
	}
	return target, err
}

// devices loads the selectable inventory, e.g. two account devices -> the other device only.
func (c cloudClient) devices(ctx context.Context, creds credentials) ([]device, error) {
	var inventory struct {
		Owned  []device `json:"my_binded_devices"`
		Shared []device `json:"others_shared_devices"`
	}
	if _, err := c.request(ctx, creds, http.MethodGet, "/api/v1/device/list", nil, &inventory); err != nil {
		return nil, err
	}
	result := make([]device, 0, len(inventory.Owned)+len(inventory.Shared))
	seen := map[string]bool{creds.DeviceID: true}
	for _, candidate := range append(inventory.Owned, inventory.Shared...) {
		if !validDeviceID(candidate.ID) || seen[candidate.ID] {
			continue
		}
		seen[candidate.ID] = true
		if candidate.Alias != "" {
			candidate.Name = candidate.Alias
		}
		if candidate.Name == "" {
			candidate.Name = candidate.DeviceName
		}
		if candidate.Name == "" {
			candidate.Name = candidate.ID
		}
		result = append(result, device{ID: candidate.ID, Name: candidate.Name})
	}
	return result, nil
}

// validDeviceID accepts a single opaque identifier, e.g. "12345" -> true and ".." -> false.
func validDeviceID(id string) bool {
	return id != "" && len(id) <= 256 && id != "." && id != ".." && !strings.ContainsAny(id, "\x00\n\r")
}
