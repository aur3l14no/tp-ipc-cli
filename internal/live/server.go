package live

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aur3l14no/tp-ipc-cli/internal/config"
	"github.com/aur3l14no/tp-ipc-cli/internal/ipc"
)

//go:embed ui.html
var uiHTML []byte

const sessionCookieName = "tp_ipc_live"

type Options struct {
	ListenAddr  string
	HighQuality bool
	Token       string
	Overrides   config.Overrides
	FFmpegBin   string
}

type CameraEntry struct {
	Name    string `json:"name"`
	Host    string `json:"host"`
	Default bool   `json:"default"`
}

type Server struct {
	opts          Options
	token         string
	defaultCamera string
	cameras       map[string]config.Settings

	mu      sync.Mutex
	clients map[string]*ipc.Client
	hub     *streamHub
}

func NewServer(opts Options) (*Server, error) {
	if strings.TrimSpace(opts.ListenAddr) == "" {
		opts.ListenAddr = "127.0.0.1:0"
	}

	st, storeErr := config.LoadStore()
	if storeErr != nil {
		// Propagate config permission/syntax errors; ignore missing config if flags/env supply a camera.
		return nil, storeErr
	}

	primaryCfg, loadErr := config.Load(opts.Overrides)
	if loadErr != nil {
		canFallbackToPicker := st.DefaultCamera == "" &&
			len(st.Cameras) > 1 &&
			strings.TrimSpace(opts.Overrides.Camera) == "" &&
			strings.TrimSpace(os.Getenv("IPC_CAMERA")) == "" &&
			strings.TrimSpace(opts.Overrides.Host) == "" &&
			strings.TrimSpace(opts.Overrides.User) == "" &&
			strings.TrimSpace(opts.Overrides.PasswordFile) == "" &&
			!opts.Overrides.PasswordStdin
		if !canFallbackToPicker {
			return nil, loadErr
		}
	}

	var ovProxy config.ProxySpec
	if strings.TrimSpace(opts.Overrides.Proxy) != "" {
		var pErr error
		ovProxy, pErr = config.ParseProxyInput(opts.Overrides.Proxy)
		if pErr != nil {
			return nil, pErr
		}
	}
	var envProxy config.ProxySpec
	if ovProxy.Kind == "" && !ovProxy.DirectOverride {
		rawEnvProxy := strings.TrimSpace(os.Getenv("IPC_PROXY"))
		if rawEnvProxy == "" {
			if rawSSH := strings.TrimSpace(os.Getenv("IPC_SSH")); rawSSH != "" {
				rawEnvProxy = config.EnsureSSHProxyPrefix(rawSSH)
			}
		}
		if rawEnvProxy != "" {
			var pErr error
			envProxy, pErr = config.ParseProxyInput(rawEnvProxy)
			if pErr != nil {
				return nil, pErr
			}
		}
	}

	cams := make(map[string]config.Settings, len(st.Cameras)+1)
	for name, cfg := range st.Cameras {
		if cfg.Host != "" {
			cfg.Name = name
			if ovProxy.DirectOverride && strings.TrimSpace(opts.Overrides.Camera) == "" {
				cfg.Proxy = ""
			} else if ovProxy.Kind != "" && strings.TrimSpace(opts.Overrides.Camera) == "" {
				cfg.Proxy = ovProxy.Canonical()
			} else if cfg.Proxy == "" && envProxy.Kind != "" {
				cfg.Proxy = envProxy.Canonical()
			}
			cams[name] = cfg
		}
	}

	defaultCam := st.DefaultCamera
	if loadErr == nil && primaryCfg.Host != "" {
		name := primaryCfg.Name
		if name == "" {
			name = "default"
			primaryCfg.Name = name
		}
		cams[name] = primaryCfg
		defaultCam = name
	}

	if len(cams) == 0 {
		return nil, errors.New("no camera configured (run `tp-ipc camera add <name> --host <ip>` or pass `--host <ip>`)")
	}
	if defaultCam == "" || cams[defaultCam].Host == "" {
		names := sortedCameraNames(cams)
		defaultCam = names[0]
	}

	tok := strings.TrimSpace(opts.Token)
	if tok == "" {
		var rnd [16]byte
		if _, err := rand.Read(rnd[:]); err != nil {
			return nil, fmt.Errorf("generate live session token: %w", err)
		}
		tok = hex.EncodeToString(rnd[:])
	}

	return &Server{
		opts:          opts,
		token:         tok,
		defaultCamera: defaultCam,
		cameras:       cams,
		clients:       make(map[string]*ipc.Client),
		hub:           newStreamHub(opts.FFmpegBin),
	}, nil
}

func sortedCameraNames(m map[string]config.Settings) []string {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

func (s *Server) Token() string {
	return s.token
}

func (s *Server) DefaultCamera() string {
	return s.defaultCamera
}

func (s *Server) Close() {
	s.hub.closeAll()
	s.mu.Lock()
	clients := make([]*ipc.Client, 0, len(s.clients))
	for _, c := range s.clients {
		clients = append(clients, c)
	}
	s.mu.Unlock()
	for _, c := range clients {
		_ = c.Close()
	}
}

func (s *Server) stopCameraStreams(cameraName string) {
	s.hub.mu.Lock()
	var toStop []*streamSession
	for k, sess := range s.hub.sessions {
		if k.camera == cameraName {
			toStop = append(toStop, sess)
			delete(s.hub.sessions, k)
		}
	}
	s.hub.mu.Unlock()
	for _, sess := range toStop {
		sess.stop()
	}
}

func (s *Server) clientFor(name string) (*ipc.Client, string, error) {
	target := strings.TrimSpace(name)
	if target == "" {
		target = s.defaultCamera
	}
	cfg, ok := s.cameras[target]
	if !ok {
		return nil, "", fmt.Errorf("camera %q not found", target)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if c, exists := s.clients[target]; exists {
		return c, target, nil
	}
	c, err := ipc.NewClient(cfg)
	if err != nil {
		return nil, "", err
	}
	s.clients[target] = c
	return c, target, nil
}

// Start binds the TCP listener and begins serving HTTP requests in the background until ctx is canceled or Shutdown is called.
func (s *Server) Start(ctx context.Context) (baseURL string, authURL string, waitFn func() error, err error) {
	ln, err := net.Listen("tcp", s.opts.ListenAddr)
	if err != nil {
		return "", "", nil, fmt.Errorf("listen %s: %w", s.opts.ListenAddr, err)
	}

	tcpAddr := ln.Addr().(*net.TCPAddr)
	displayHost := tcpAddr.IP.String()
	if tcpAddr.IP.IsUnspecified() {
		displayHost = "127.0.0.1"
	}
	baseURL = fmt.Sprintf("http://%s", net.JoinHostPort(displayHost, fmt.Sprintf("%d", tcpAddr.Port)))
	authURL = fmt.Sprintf("%s/?token=%s", baseURL, url.QueryEscape(s.token))

	httpSrv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
		// WriteTimeout intentionally 0 so long-running /api/stream fMP4 responses are never cut off.
	}

	errCh := make(chan error, 1)
	go func() {
		srvErr := httpSrv.Serve(ln)
		if errors.Is(srvErr, http.ErrServerClosed) {
			srvErr = nil
		}
		errCh <- srvErr
	}()

	go func() {
		<-ctx.Done()
		s.Close()
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
	}()

	return baseURL, authURL, func() error {
		return <-errCh
	}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/bootstrap", s.handleBootstrap)
	mux.HandleFunc("/api/state", s.handleState)
	mux.HandleFunc("/api/stream", s.handleStream)
	mux.HandleFunc("/api/snapshot", s.handleSnapshot)
	mux.HandleFunc("/api/ptz", s.handlePTZ)
	mux.HandleFunc("/api/preset", s.handlePreset)
	mux.HandleFunc("/api/control", s.handleControl)
	return s.securityMiddleware(mux)
}

func (s *Server) validToken(candidate string) bool {
	if len(candidate) != len(s.token) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(candidate), []byte(s.token)) == 1
}

func (s *Server) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")

		// Exchange ?token=... on GET / into an HttpOnly SameSite=Strict cookie and strip it from the URL.
		if r.Method == http.MethodGet && r.URL.Path == "/" {
			if qTok := r.URL.Query().Get("token"); qTok != "" && s.validToken(qTok) {
				http.SetCookie(w, &http.Cookie{
					Name:     sessionCookieName,
					Value:    s.token,
					Path:     "/",
					HttpOnly: true,
					SameSite: http.SameSiteStrictMode,
				})
				cleanQuery := r.URL.Query()
				cleanQuery.Del("token")
				target := "/"
				if enc := cleanQuery.Encode(); enc != "" {
					target = "/?" + enc
				}
				http.Redirect(w, r, target, http.StatusSeeOther)
				return
			}
		}

		authed := false
		usedBearer := false
		if authHdr := r.Header.Get("Authorization"); strings.HasPrefix(authHdr, "Bearer ") {
			if s.validToken(strings.TrimSpace(strings.TrimPrefix(authHdr, "Bearer "))) {
				authed = true
				usedBearer = true
			}
		}
		if !authed {
			if ck, err := r.Cookie(sessionCookieName); err == nil && s.validToken(ck.Value) {
				authed = true
			}
		}
		if !authed {
			if r.Method == http.MethodGet && r.URL.Path == "/" {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(w, unauthorizedHTML)
				return
			}
			writeAPIError(w, http.StatusUnauthorized, "unauthorized: open the full URL with ?token=... printed by `tp-ipc live`")
			return
		}

		// Require custom header on cookie-authenticated mutations to prevent cross-origin form POST CSRF.
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !usedBearer && r.Header.Get("X-Requested-With") != "tp-ipc" {
				writeAPIError(w, http.StatusForbidden, "missing X-Requested-With header")
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

const unauthorizedHTML = `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>tp-ipc live — 需要会话令牌</title>
<style>
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b0e14;color:#e6edf3;font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.card{max-width:420px;padding:24px;border-radius:12px;background:#131822;border:1px solid #242d3d}
h1{margin:0 0 8px;font-size:16px}p{margin:0 0 16px;color:#8b98ad}
form{display:flex;gap:8px}input{flex:1;padding:8px 10px;border-radius:8px;border:1px solid #2d384c;background:#0b0e14;color:#e6edf3;font-family:monospace}
button{padding:8px 14px;border-radius:8px;border:0;background:#3b82f6;color:#fff;font-weight:600;cursor:pointer}
</style></head><body><div class="card">
<h1>需要访问令牌</h1>
<p>请直接打开终端里打印的完整链接（含 <code>?token=...</code>），或在下方粘贴本次会话 Token：</p>
<form method="get" action="/"><input name="token" placeholder="粘贴会话 token" autofocus required><button type="submit">进入</button></form>
</div></body></html>`

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(uiHTML)
}

func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	names := sortedCameraNames(s.cameras)
	list := make([]CameraEntry, 0, len(names))
	for _, n := range names {
		c := s.cameras[n]
		list = append(list, CameraEntry{
			Name:    n,
			Host:    c.Host,
			Default: n == s.defaultCamera,
		})
	}
	defQuality := "sub"
	if s.opts.HighQuality {
		defQuality = "main"
	}
	writeAPIJSON(w, http.StatusOK, map[string]any{
		"default_camera":  s.defaultCamera,
		"default_quality": defQuality,
		"cameras":         list,
	})
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	client, camName, err := s.clientFor(r.URL.Query().Get("camera"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var (
		wg        sync.WaitGroup
		info      ipc.DeviceInfo
		infoErr   error
		status    ipc.CameraStatus
		statusErr error
		ptz       *ipc.PTZPosition
		presets   []ipc.Preset
	)

	wg.Add(4)
	go func() {
		defer wg.Done()
		info, infoErr = client.DeviceInfo(ctx)
	}()
	go func() {
		defer wg.Done()
		status, statusErr = client.CameraStatus(ctx)
	}()
	go func() {
		defer wg.Done()
		if p, pErr := client.PTZStatus(ctx); pErr == nil {
			ptz = &p
		}
	}()
	go func() {
		defer wg.Done()
		if list, _, lErr := client.ListPresets(ctx); lErr == nil {
			presets = list
		}
	}()
	wg.Wait()

	if statusErr != nil && infoErr != nil {
		writeAPIError(w, http.StatusBadGateway, client.Redact(statusErr.Error()))
		return
	}
	if presets == nil {
		presets = []ipc.Preset{}
	}

	writeAPIJSON(w, http.StatusOK, map[string]any{
		"camera":  camName,
		"host":    client.Settings().Host,
		"proxy":   client.Settings().RedactedProxy(),
		"info":    info,
		"status":  status,
		"ptz":     ptz,
		"presets": presets,
	})
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	client, camName, err := s.clientFor(r.URL.Query().Get("camera"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}

	quality := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("quality")))
	if quality != "main" && quality != "4k" && quality != "hq" {
		quality = "sub"
	} else {
		quality = "main"
	}

	codec := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("codec")))
	if codec != "h264" {
		codec = "copy"
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, "streaming unsupported by response writer")
		return
	}

	sub, err := s.hub.subscribe(r.Context(), streamKey{
		camera:  camName,
		quality: quality,
		codec:   codec,
	}, client)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		writeAPIError(w, http.StatusBadGateway, client.Redact(err.Error()))
		return
	}
	defer sub.Close()

	w.Header().Set("Content-Type", "video/mp4")
	w.Header().Set("X-Stream-Mime", sub.mime)
	w.Header().Set("X-Stream-Codec-Mode", codec)
	w.WriteHeader(http.StatusOK)

	if _, err := w.Write(sub.initSeg); err != nil {
		return
	}
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-sub.doneCh:
			// Drain any remaining queued fragments before closing HTTP stream
			for {
				select {
				case frag := <-sub.ch:
					if _, wErr := w.Write(frag); wErr != nil {
						return
					}
					flusher.Flush()
				default:
					return
				}
			}
		case frag := <-sub.ch:
			if _, wErr := w.Write(frag); wErr != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	client, camName, err := s.clientFor(r.URL.Query().Get("camera"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	hq := r.URL.Query().Get("hq") == "1" || r.URL.Query().Get("hq") == "true"
	jpegBytes, err := client.Snapshot(r.Context(), ipc.SnapshotOptions{
		HighQuality: hq,
		Zoom:        1,
		FocusX:      0.5,
		FocusY:      0.5,
	})
	if err != nil {
		writeAPIError(w, http.StatusBadGateway, client.Redact(err.Error()))
		return
	}

	safeName := config.SanitizeProfileToken(camName)
	if safeName == "" {
		safeName = "ipc"
	}
	filename := fmt.Sprintf("snap-%s-%s.jpg", safeName, time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Type", "image/jpeg")
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	}
	_, _ = w.Write(jpegBytes)
}

func (s *Server) handlePTZ(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Camera string  `json:"camera"`
		Action string  `json:"action"`
		Pan    float64 `json:"pan"`
		Tilt   float64 `json:"tilt"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	client, _, err := s.clientFor(req.Camera)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	switch req.Action {
	case "move":
		err = client.PTZMoveRelative(ctx, req.Pan, req.Tilt)
	case "goto":
		err = client.PTZMoveAbsolute(ctx, req.Pan, req.Tilt)
	case "stop":
		err = client.PTZStop(ctx)
	default:
		writeAPIError(w, http.StatusBadRequest, fmt.Sprintf("unknown PTZ action %q", req.Action))
		return
	}
	if err != nil {
		writeAPIError(w, http.StatusBadGateway, client.Redact(err.Error()))
		return
	}

	var pos *ipc.PTZPosition
	if p, pErr := client.PTZStatus(ctx); pErr == nil {
		pos = &p
	}
	writeAPIJSON(w, http.StatusOK, map[string]any{"ok": true, "ptz": pos})
}

func (s *Server) handlePreset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Camera string `json:"camera"`
		Action string `json:"action"`
		ID     string `json:"id"`
		Name   string `json:"name"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	client, _, err := s.clientFor(req.Camera)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	switch req.Action {
	case "goto":
		_, err = client.GotoPreset(ctx, req.ID)
	case "save":
		_, err = client.SavePreset(ctx, req.Name)
	case "remove":
		err = client.RemovePreset(ctx, req.ID)
	default:
		writeAPIError(w, http.StatusBadRequest, fmt.Sprintf("unknown preset action %q", req.Action))
		return
	}
	if err != nil {
		writeAPIError(w, http.StatusBadGateway, client.Redact(err.Error()))
		return
	}

	presets, _, _ := client.ListPresets(ctx)
	if presets == nil {
		presets = []ipc.Preset{}
	}
	writeAPIJSON(w, http.StatusOK, map[string]any{"ok": true, "presets": presets})
}

func (s *Server) handleControl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Camera  string `json:"camera"`
		Target  string `json:"target"`
		Enabled *bool  `json:"enabled,omitempty"`
		Mode    string `json:"mode,omitempty"`
		Kind    string `json:"kind,omitempty"`
		Volume  *int   `json:"volume,omitempty"`
		Action  string `json:"action,omitempty"`
		Seconds int    `json:"seconds,omitempty"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	client, camName, err := s.clientFor(req.Camera)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	requireEnabled := func() (bool, error) {
		if req.Enabled == nil {
			return false, errors.New("missing boolean 'enabled' field")
		}
		return *req.Enabled, nil
	}

	switch req.Target {
	case "privacy":
		en, bErr := requireEnabled()
		if bErr != nil {
			writeAPIError(w, http.StatusBadRequest, bErr.Error())
			return
		}
		_, err = client.SetPrivacy(ctx, en)
		if err == nil {
			s.stopCameraStreams(camName)
		}
	case "led":
		en, bErr := requireEnabled()
		if bErr != nil {
			writeAPIError(w, http.StatusBadRequest, bErr.Error())
			return
		}
		_, err = client.SetLED(ctx, en)
	case "tracking":
		en, bErr := requireEnabled()
		if bErr != nil {
			writeAPIError(w, http.StatusBadRequest, bErr.Error())
			return
		}
		_, err = client.SetTracking(ctx, en)
	case "detect":
		en, bErr := requireEnabled()
		if bErr != nil {
			writeAPIError(w, http.StatusBadRequest, bErr.Error())
			return
		}
		_, err = client.SetDetection(ctx, req.Kind, en)
	case "night_vision":
		_, err = client.SetNightVision(ctx, req.Mode)
	case "volume":
		if req.Volume == nil {
			writeAPIError(w, http.StatusBadRequest, "missing 'volume' field")
			return
		}
		_, err = client.SetSpeakerVolume(ctx, *req.Volume)
	case "alarm":
		if req.Action == "stop" {
			err = client.StopAlarm(ctx)
		} else {
			sec := req.Seconds
			if sec <= 0 {
				sec = 2
			}
			err = client.TriggerAlarm(ctx, sec)
		}
	default:
		writeAPIError(w, http.StatusBadRequest, fmt.Sprintf("unknown control target %q", req.Target))
		return
	}

	if err != nil {
		writeAPIError(w, http.StatusBadGateway, client.Redact(err.Error()))
		return
	}
	writeAPIJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func decodeJSONBody(r *http.Request, dst any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 64*1024))
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON request body: %w", err)
	}
	return nil
}

func writeAPIJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeAPIError(w http.ResponseWriter, code int, msg string) {
	writeAPIJSON(w, code, map[string]any{"error": msg})
}
