package ipc

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/aur3l14no/tp-ipc-cli/internal/config"
)

const (
	ErrCodeSessionExpired  = -40401
	ErrCodeSessionTimeout  = -40403
	ErrCodeLocked          = -40404
	ErrCodeNeedsPassChange = -40405
	ErrCodeClientFull      = -40406
	ErrCodeActivated       = -40407
	ErrCodeLockedForever   = -40408
	ErrCodeSuperPwdSuccess = -40409
	ErrCodeNeedsActivation = -40414
)

type APIError struct {
	Code    int
	Message string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("camera API error %d (%s)", e.Code, e.Message)
	}
	return fmt.Sprintf("camera API error %d", e.Code)
}

func describeErrorCode(code int) string {
	switch code {
	case -40401:
		return "session expired or unauthorized"
	case -40403:
		return "session timed out"
	case -40404, -40413:
		return "account temporarily locked due to failed attempts"
	case -40405:
		return "password change required"
	case -40406:
		return "too many active camera sessions"
	case -40407:
		return "authentication required"
	case -40408:
		return "account locked"
	case -40410:
		return "login nonce expired"
	case -40411:
		return "unsupported username"
	case -40414:
		return "camera requires initial activation"
	case -40209, -40210:
		return "invalid parameter or unsupported action"
	case -71108:
		return "invalid recording date parameter"
	case -71112:
		return "invalid playback session user_id"
	default:
		return ""
	}
}

type Client struct {
	cfg            config.Settings
	httpClient     *http.Client
	longPollClient *http.Client

	loginMu sync.Mutex
	stateMu sync.RWMutex
	stok    string
	userID  int
}

func NewClient(cfg config.Settings) (*Client, error) {
	if cfg.Host == "" {
		return nil, errors.New("camera host is not configured (set IPC_HOST, --host, or run `tp-ipc configure`)")
	}
	dialFn := (&net.Dialer{
		Timeout:   6 * time.Second,
		KeepAlive: 15 * time.Second,
	}).DialContext
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, // Local camera uses self-signed certs when HTTPS is enabled
		MinVersion:         tls.VersionTLS10,
	}
	transport := &http.Transport{
		Proxy:                 nil, // Never route LAN camera traffic through system/env HTTP proxies
		DialContext:           dialFn,
		TLSClientConfig:       tlsCfg,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
	longPollTransport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialFn,
		TLSClientConfig:       tlsCfg.Clone(),
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: 0, // Governed by per-request context deadline during ONVIF PullMessages
	}
	return &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   12 * time.Second,
		},
		longPollClient: &http.Client{
			Transport: longPollTransport,
		},
	}, nil
}

func (c *Client) Settings() config.Settings {
	return c.cfg
}

func (c *Client) currentStok() string {
	c.stateMu.RLock()
	stok := c.stok
	c.stateMu.RUnlock()
	return stok
}

func (c *Client) Redact(text string) string {
	return c.cfg.Redact(text, c.currentStok())
}

func (c *Client) rawHTTP(ctx context.Context, targetURL string, method string, body []byte, headers map[string]string) (int, []byte, error) {
	return c.rawHTTPWithClient(ctx, c.httpClient, targetURL, method, body, headers)
}

func (c *Client) rawHTTPLongPoll(ctx context.Context, targetURL string, method string, body []byte, headers map[string]string) (int, []byte, error) {
	hc := c.longPollClient
	if hc == nil {
		hc = c.httpClient
	}
	return c.rawHTTPWithClient(ctx, hc, targetURL, method, body, headers)
}

func (c *Client) rawHTTPWithClient(ctx context.Context, hc *http.Client, targetURL string, method string, body []byte, headers map[string]string) (int, []byte, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, targetURL, bodyReader)
	if err != nil {
		return 0, nil, errors.New(c.Redact(err.Error()))
	}
	req.Header.Set("User-Agent", "TP-LINK_APP")
	if body != nil && len(headers) == 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if _, isSOAP := headers["SOAPAction"]; isSOAP {
		// TP-Link's embedded ONVIF daemon on port 2020 corrupts buffers on reused keep-alive sockets.
		req.Close = true
	}

	resp, err := hc.Do(req)
	if err != nil {
		msg := c.Redact(err.Error())
		if hint := macosLocalNetworkHint(err, c.cfg.Host); hint != "" {
			msg += " " + hint
		}
		return 0, nil, fmt.Errorf("camera HTTP request failed: %s", msg)
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("read camera HTTP response: %s", c.Redact(err.Error()))
	}
	return resp.StatusCode, respBytes, nil
}

func macosLocalNetworkHint(err error, host string) string {
	if runtime.GOOS != "darwin" || !errors.Is(err, syscall.EHOSTUNREACH) {
		return ""
	}
	ip := net.ParseIP(host)
	if ip == nil || (!ip.IsPrivate() && !ip.IsLinkLocalUnicast()) {
		return ""
	}
	return "(on macOS, EHOSTUNREACH / \"no route to host\" to a local LAN IP usually means System Settings -> Privacy & Security -> Local Network is turned off for your terminal or host app)"
}

type challengePayload struct {
	ErrorCode int `json:"error_code"`
	Data      struct {
		Code           int      `json:"code"`
		Key            string   `json:"key"`
		Nonce          string   `json:"nonce"`
		EncryptType    []string `json:"encrypt_type"`
		MD5EncryptType any      `json:"md5_encrypt_type"`
		SecLeft        int      `json:"sec_left"`
	} `json:"data"`
}

func containsString(items []string, target string) bool {
	for _, s := range items {
		if s == target {
			return true
		}
	}
	return false
}

func (c *Client) fetchChallenge(ctx context.Context) (challengePayload, int, error) {
	var ch challengePayload
	status, body, err := c.rawHTTP(ctx, c.cfg.HTTPBaseURL()+"/pc/Content.htm", http.MethodGet, nil, nil)
	if err != nil {
		return ch, 0, err
	}
	if err := json.Unmarshal(body, &ch); err != nil {
		return ch, status, fmt.Errorf("unexpected response from /pc/Content.htm (HTTP %d)", status)
	}
	return ch, status, nil
}

func (c *Client) ensureSession(ctx context.Context) (string, error) {
	if stok := c.currentStok(); stok != "" {
		return stok, nil
	}
	c.loginMu.Lock()
	defer c.loginMu.Unlock()

	if stok := c.currentStok(); stok != "" {
		return stok, nil
	}
	if c.cfg.User == "" || c.cfg.Password == "" {
		return "", errors.New("camera credentials missing (set IPC_PASSWORD, --password-stdin, or run `tp-ipc configure`)")
	}
	ch, status, err := c.fetchChallenge(ctx)
	if err != nil {
		return "", err
	}
	if status != http.StatusUnauthorized && ch.Data.Key == "" && ch.Data.Nonce == "" {
		return "", fmt.Errorf("camera did not return login challenge (HTTP %d)", status)
	}
	if ch.Data.Code == ErrCodeNeedsActivation {
		return "", errors.New("camera is unactivated; complete initial activation in the TP-LINK app or web UI first")
	}
	if ch.Data.Code == ErrCodeNeedsPassChange {
		return "", errors.New("camera requires an initial password change in the TP-LINK app or web UI first")
	}

	md5Mode := jsonInt(ch.Data.MD5EncryptType, 0) == 1
	hasRSA := containsString(ch.Data.EncryptType, "2") || (len(ch.Data.EncryptType) == 0 && ch.Data.Key != "")
	encType := "1"
	if hasRSA {
		encType = "2"
	}

	var cipherPwd string
	switch {
	case md5Mode:
		if ch.Data.Nonce == "" {
			return "", fmt.Errorf("incomplete login challenge from camera (code %d)", ch.Data.Code)
		}
		cipherPwd, err = MD5LoginPassword(c.cfg.Password, ch.Data.Nonce)
		if err != nil {
			return "", err
		}
	case hasRSA:
		if ch.Data.Key == "" || ch.Data.Nonce == "" {
			return "", fmt.Errorf("incomplete login challenge from camera (code %d)", ch.Data.Code)
		}
		cipherPwd, err = EncryptLoginPassword(c.cfg.Password, ch.Data.Nonce, ch.Data.Key)
		if err != nil {
			return "", err
		}
	default:
		cipherPwd, err = SecurityEncode(c.cfg.Password)
		if err != nil {
			return "", err
		}
	}

	loginFields := map[string]any{
		"username":     c.cfg.User,
		"password":     cipherPwd,
		"encrypt_type": encType,
	}
	if md5Mode {
		loginFields["md5_encrypt_type"] = "1"
	}
	loginReq := map[string]any{
		"method": "do",
		"login":  loginFields,
	}
	reqBytes, _ := json.Marshal(loginReq)
	lStatus, lBody, err := c.rawHTTP(ctx, c.cfg.HTTPBaseURL()+"/", http.MethodPost, reqBytes, nil)
	if err != nil {
		return "", err
	}
	var loginResp struct {
		ErrorCode int    `json:"error_code"`
		Stok      string `json:"stok"`
		Data      struct {
			Code    int `json:"code"`
			SecLeft int `json:"sec_left"`
		} `json:"data"`
	}
	if err := json.Unmarshal(lBody, &loginResp); err != nil {
		return "", fmt.Errorf("invalid JSON from camera login (HTTP %d)", lStatus)
	}
	loginOK := (loginResp.ErrorCode == 0 || loginResp.ErrorCode == ErrCodeSuperPwdSuccess) && loginResp.Stok != ""
	if !loginOK {
		code := loginResp.ErrorCode
		if loginResp.Data.Code != 0 {
			code = loginResp.Data.Code
		}
		desc := describeErrorCode(code)
		if code == ErrCodeLocked && loginResp.Data.SecLeft > 0 {
			desc = fmt.Sprintf("account temporarily locked (%ds remaining)", loginResp.Data.SecLeft)
		}
		msg := "camera login rejected"
		if desc != "" {
			msg += ": " + desc
		}
		return "", &APIError{Code: code, Message: msg}
	}
	decodedStok, err := url.PathUnescape(loginResp.Stok)
	if err != nil {
		decodedStok = loginResp.Stok
	}
	c.stateMu.Lock()
	c.stok = decodedStok
	c.userID = 0
	c.stateMu.Unlock()
	return decodedStok, nil
}

// DoDS executes a JSON request against /stok=<token>/ds, logging in and retrying once on session expiry.
func (c *Client) DoDS(ctx context.Context, payload any) (map[string]any, error) {
	reqBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	for attempt := 0; attempt < 2; attempt++ {
		stok, err := c.ensureSession(ctx)
		if err != nil {
			return nil, err
		}

		endpoint := fmt.Sprintf("%s/stok=%s/ds", c.cfg.HTTPBaseURL(), url.PathEscape(stok))
		status, body, err := c.rawHTTP(ctx, endpoint, http.MethodPost, reqBytes, nil)
		if err != nil {
			return nil, err
		}
		if status == http.StatusUnauthorized || status == http.StatusForbidden {
			c.invalidateStok(stok)
			continue
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("camera /ds returned HTTP %d", status)
		}

		var result map[string]any
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, errors.New("invalid JSON from camera /ds")
		}
		errCode := jsonInt(result["error_code"], -1)
		if errCode == ErrCodeSessionExpired || errCode == ErrCodeSessionTimeout {
			c.invalidateStok(stok)
			continue
		}
		if errCode != 0 {
			return nil, &APIError{Code: errCode, Message: describeErrorCode(errCode)}
		}
		return result, nil
	}
	return nil, errors.New("camera session expired after retry")
}

// DoDSWithUserID obtains the playback session user_id and runs a factory-built /ds request.
func (c *Client) DoDSWithUserID(ctx context.Context, buildPayload func(userID int) any) (map[string]any, error) {
	for attempt := 0; attempt < 2; attempt++ {
		uid, err := c.ensureUserID(ctx)
		if err != nil {
			return nil, err
		}
		res, err := c.DoDS(ctx, buildPayload(uid))
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.Code == -71112 && attempt == 0 {
			c.stateMu.Lock()
			c.userID = 0
			c.stateMu.Unlock()
			continue
		}
		return res, err
	}
	return nil, errors.New("failed to acquire valid playback user_id")
}

func (c *Client) ensureUserID(ctx context.Context) (int, error) {
	c.stateMu.RLock()
	uid := c.userID
	c.stateMu.RUnlock()
	if uid > 0 {
		return uid, nil
	}

	res, err := c.DoDS(ctx, map[string]any{
		"method": "do",
		"system": map[string]any{"get_user_id": "null"},
	})
	if err != nil {
		return 0, err
	}
	uid = jsonInt(res["user_id"], 0)
	if uid <= 0 {
		return 0, errors.New("camera did not return a valid user_id")
	}
	c.stateMu.Lock()
	c.userID = uid
	c.stateMu.Unlock()
	return uid, nil
}

func (c *Client) invalidateStok(old string) {
	c.stateMu.Lock()
	if c.stok == old {
		c.stok = ""
		c.userID = 0
	}
	c.stateMu.Unlock()
}

func (c *Client) GetModule(ctx context.Context, module string, sections ...string) (map[string]any, error) {
	res, err := c.DoDS(ctx, map[string]any{
		"method": "get",
		module:   map[string]any{"name": sections},
	})
	if err != nil {
		return nil, err
	}
	return asMap(res[module]), nil
}

func (c *Client) SetModule(ctx context.Context, module, section string, value any) (map[string]any, error) {
	return c.DoDS(ctx, map[string]any{
		"method": "set",
		module:   map[string]any{section: value},
	})
}

func (c *Client) ActionModule(ctx context.Context, module, action string, value any) (map[string]any, error) {
	return c.DoDS(ctx, map[string]any{
		"method": "do",
		module:   map[string]any{action: value},
	})
}

func asMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok && m != nil {
		return m
	}
	return map[string]any{}
}

func jsonInt(v any, fallback int) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return int(i)
		}
	case string:
		var n int
		if _, err := fmt.Sscanf(x, "%d", &n); err == nil {
			return n
		}
	}
	return fallback
}

func jsonFloat(v any, fallback float64) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int:
		return float64(x)
	case string:
		var f float64
		if _, err := fmt.Sscanf(x, "%f", &f); err == nil {
			return f
		}
	}
	return fallback
}

func jsonStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}
