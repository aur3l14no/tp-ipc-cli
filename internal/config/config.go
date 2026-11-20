package config

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

const (
	DefaultUser      = "admin"
	DefaultScheme    = "http"
	DefaultHTTPPort  = 80
	DefaultRTSPPort  = 554
	DefaultONVIFPort = 2020
)

type Settings struct {
	Name      string `json:"-"`
	Scheme    string `json:"scheme,omitempty"`
	Host      string `json:"host"`
	HTTPPort  int    `json:"http_port,omitempty"`
	RTSPPort  int    `json:"rtsp_port,omitempty"`
	ONVIFPort int    `json:"onvif_port,omitempty"`
	User      string `json:"user"`
	Password  string `json:"password,omitempty"`
	Proxy     string `json:"proxy,omitempty"`
	MediaDir  string `json:"media_dir,omitempty"`
}

// Store represents the multi-camera configuration file (~/.config/tp-ipc/config.json).
// Legacy top-level single-camera fields (Host, User, Password, ...) remain supported for backward compatibility.
type Store struct {
	DefaultCamera string              `json:"default_camera,omitempty"`
	MediaDir      string              `json:"media_dir,omitempty"`
	Cameras       map[string]Settings `json:"cameras,omitempty"`

	// Legacy flat single-camera fields (migrated into Cameras["default"] on load)
	Scheme    string `json:"scheme,omitempty"`
	Host      string `json:"host,omitempty"`
	HTTPPort  int    `json:"http_port,omitempty"`
	RTSPPort  int    `json:"rtsp_port,omitempty"`
	ONVIFPort int    `json:"onvif_port,omitempty"`
	User      string `json:"user,omitempty"`
	Password  string `json:"password,omitempty"`
	Proxy     string `json:"proxy,omitempty"`
}

type Overrides struct {
	Camera        string
	Host          string
	User          string
	PasswordStdin bool
	PasswordFile  string
	HTTPPort      int
	RTSPPort      int
	ONVIFPort     int
	Proxy         string
	Stdin         io.Reader
}

type CameraSummary struct {
	Name        string `json:"name"`
	Default     bool   `json:"default"`
	Scheme      string `json:"scheme"`
	Host        string `json:"host"`
	HTTPPort    int    `json:"http_port"`
	RTSPPort    int    `json:"rtsp_port"`
	ONVIFPort   int    `json:"onvif_port"`
	User        string `json:"user"`
	HasPassword bool   `json:"has_password"`
	Proxy       string `json:"proxy,omitempty"`
	Source      string `json:"source,omitempty"`
}

func ConfigPath() (string, error) {
	base := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME"))
	if base != "" {
		if !filepath.IsAbs(base) {
			return "", errors.New("XDG_CONFIG_HOME must be an absolute path")
		}
	} else {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return "", errors.New("cannot determine home directory for config")
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "tp-ipc", "config.json"), nil
}

// ValidateProfileName ensures camera profile names are safe single-token identifiers
// that cannot traverse directories when embedded into filenames.
func ValidateProfileName(name string) error {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return errors.New("camera profile name cannot be empty")
	}
	if len(trimmed) > 64 {
		return fmt.Errorf("camera profile name %q exceeds 64 characters", name)
	}
	if strings.Contains(trimmed, "..") {
		return fmt.Errorf("invalid camera profile name %q (must not contain '..')", name)
	}
	for i := 0; i < len(trimmed); i++ {
		ch := trimmed[i]
		isAlphaNum := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
		if i == 0 && !isAlphaNum {
			return fmt.Errorf("invalid camera profile name %q (must start with a letter or digit)", name)
		}
		if !isAlphaNum && ch != '-' && ch != '_' && ch != '.' {
			return fmt.Errorf("invalid camera profile name %q (allowed characters: letters, digits, '-', '_', '.')", name)
		}
	}
	return nil
}

// SanitizeProfileToken scrubs any non-identifier characters from a profile name before filename interpolation.
func SanitizeProfileToken(name string) string {
	var b strings.Builder
	for i := 0; i < len(name) && b.Len() < 64; i++ {
		ch := name[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' {
			b.WriteByte(ch)
		}
	}
	return strings.Trim(b.String(), "-_")
}

// ParseHostInput accepts "192.168.1.60", "127.0.0.1:18080", or "http://192.168.1.60:8080".
func ParseHostInput(raw string) (scheme string, host string, port int, err error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", "", 0, errors.New("empty camera host")
	}
	candidate := trimmed
	if !strings.Contains(trimmed, "://") {
		candidate = DefaultScheme + "://" + trimmed
	}
	u, err := url.Parse(candidate)
	if err != nil {
		return "", "", 0, fmt.Errorf("invalid camera address %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", "", 0, fmt.Errorf("unsupported scheme %q (expected http or https)", u.Scheme)
	}
	hostname := u.Hostname()
	if hostname == "" {
		return "", "", 0, fmt.Errorf("missing hostname in %q", raw)
	}
	if p := u.Port(); p != "" {
		n, convErr := strconv.Atoi(p)
		if convErr != nil || n < 1 || n > 65535 {
			return "", "", 0, fmt.Errorf("invalid port %q", p)
		}
		port = n
	}
	return u.Scheme, hostname, port, nil
}

func normalizeSettings(s Settings, name string, globalMediaDir string) Settings {
	s.Name = name
	if s.Host != "" {
		if scheme, host, port, err := ParseHostInput(s.Host); err == nil {
			if s.Scheme == "" {
				s.Scheme = scheme
			}
			s.Host = host
			if s.HTTPPort <= 0 && port > 0 {
				s.HTTPPort = port
			}
		}
	}
	if s.Scheme == "" {
		s.Scheme = DefaultScheme
	}
	if s.User == "" {
		s.User = DefaultUser
	}
	if s.HTTPPort <= 0 {
		if s.Scheme == "https" {
			s.HTTPPort = 443
		} else {
			s.HTTPPort = DefaultHTTPPort
		}
	}
	if s.RTSPPort <= 0 {
		s.RTSPPort = DefaultRTSPPort
	}
	if s.ONVIFPort <= 0 {
		s.ONVIFPort = DefaultONVIFPort
	}
	if s.MediaDir == "" {
		s.MediaDir = globalMediaDir
	}
	if s.Proxy != "" {
		if spec, err := ParseProxyInput(s.Proxy); err == nil {
			s.Proxy = spec.Canonical()
		}
	}
	return s
}

// LoadStore loads saved camera profiles plus environment-defined cameras (IPC_CAMERAS and IPC_HOST_<NAME> / IPC_PASSWORD_<NAME>).
func LoadStore() (Store, error) {
	st := Store{
		Cameras: make(map[string]Settings),
	}

	if path, err := ConfigPath(); err == nil {
		if info, statErr := os.Lstat(path); statErr == nil {
			if !info.Mode().IsRegular() {
				return st, fmt.Errorf("config %s must be a regular file", path)
			}
			if runtime.GOOS != "windows" && (info.Mode().Perm()&0o077) != 0 {
				return st, fmt.Errorf("config %s has insecure permissions %04o (expected 0600)", path, info.Mode().Perm())
			}
			if info.Size() > 65536 {
				return st, fmt.Errorf("config %s is unexpectedly large", path)
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return st, fmt.Errorf("cannot read config %s: %w", path, readErr)
			}
			if jsonErr := json.Unmarshal(data, &st); jsonErr != nil {
				return st, fmt.Errorf("invalid JSON in %s: %w", path, jsonErr)
			}
			if st.Cameras == nil {
				st.Cameras = make(map[string]Settings)
			}
			// Migrate legacy flat config into "default" profile transparently
			if st.Host != "" && len(st.Cameras) == 0 {
				st.Cameras["default"] = Settings{
					Scheme:    st.Scheme,
					Host:      st.Host,
					HTTPPort:  st.HTTPPort,
					RTSPPort:  st.RTSPPort,
					ONVIFPort: st.ONVIFPort,
					User:      st.User,
					Password:  st.Password,
					Proxy:     st.Proxy,
				}
				if st.DefaultCamera == "" {
					st.DefaultCamera = "default"
				}
				st.Scheme, st.Host, st.User, st.Password, st.Proxy = "", "", "", "", ""
				st.HTTPPort, st.RTSPPort, st.ONVIFPort = 0, 0, 0
			}
		}
	}

	if v := strings.TrimSpace(os.Getenv("IPC_MEDIA_DIR")); v != "" {
		st.MediaDir = v
	}

	// Merge IPC_CAMERAS JSON map if provided: e.g. '{"desk":{"host":"192.168.1.60"},"door":{"host":"192.168.1.61"}}'
	if rawCams := strings.TrimSpace(os.Getenv("IPC_CAMERAS")); rawCams != "" {
		var envCams map[string]Settings
		if err := json.Unmarshal([]byte(rawCams), &envCams); err != nil {
			return st, fmt.Errorf("invalid IPC_CAMERAS JSON: %w", err)
		}
		for name, cam := range envCams {
			existing := st.Cameras[name]
			applySaved(&existing, cam)
			st.Cameras[name] = existing
		}
	}

	// Scan IPC_HOST_<KEY>, IPC_USER_<KEY>, IPC_PASSWORD_<KEY> so secret managers and container orchestrators can inject per-camera secrets cleanly.
	applyIndexedEnvVars(&st)

	// Single-camera IPC_HOST fallback registers/updates "default" when no named camera is targeted
	if singleHost := strings.TrimSpace(os.Getenv("IPC_HOST")); singleHost != "" && len(st.Cameras) == 0 {
		cam := Settings{Host: singleHost}
		if u := strings.TrimSpace(os.Getenv("IPC_USER")); u != "" {
			cam.User = u
		}
		if p := os.Getenv("IPC_PASSWORD"); p != "" {
			cam.Password = p
		}
		st.Cameras["default"] = cam
		if st.DefaultCamera == "" {
			st.DefaultCamera = "default"
		}
	}

	if defEnv := strings.TrimSpace(os.Getenv("IPC_CAMERA")); defEnv != "" {
		st.DefaultCamera = defEnv
	}
	if st.DefaultCamera == "" && len(st.Cameras) == 1 {
		for k := range st.Cameras {
			st.DefaultCamera = k
		}
	}
	for k, v := range st.Cameras {
		if err := ValidateProfileName(k); err != nil {
			return st, err
		}
		if strings.TrimSpace(v.Proxy) != "" {
			spec, pErr := ParseProxyInput(v.Proxy)
			if pErr != nil {
				return st, fmt.Errorf("camera %q: %w", k, pErr)
			}
			v.Proxy = spec.Canonical()
		}
		st.Cameras[k] = normalizeSettings(v, k, st.MediaDir)
	}
	return st, nil
}

func envKeyToProfileName(suffix string) string {
	return strings.ToLower(strings.TrimSpace(suffix))
}

func profileNameToEnvSuffix(name string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(name) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func applyIndexedEnvVars(st *Store) {
	// First discover any new profiles declared via IPC_HOST_<NAME>
	for _, kv := range os.Environ() {
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			continue
		}
		key, val := kv[:eq], kv[eq+1:]
		if strings.HasPrefix(key, "IPC_HOST_") && val != "" {
			suffix := key[len("IPC_HOST_"):]
			matchName := findMatchingProfile(st.Cameras, suffix)
			cam := st.Cameras[matchName]
			_ = applyHost(&cam, val)
			st.Cameras[matchName] = cam
		}
	}
	// Apply per-profile IPC_USER_<NAME>, IPC_PASSWORD_<NAME>, IPC_HTTP_PORT_<NAME>, IPC_RTSP_PORT_<NAME>, IPC_ONVIF_PORT_<NAME>
	for name, cam := range st.Cameras {
		sfx := profileNameToEnvSuffix(name)
		if sfx == "" {
			continue
		}
		if v := strings.TrimSpace(os.Getenv("IPC_HOST_" + sfx)); v != "" {
			_ = applyHost(&cam, v)
		}
		if v := strings.TrimSpace(os.Getenv("IPC_USER_" + sfx)); v != "" {
			cam.User = v
		}
		if v := os.Getenv("IPC_PASSWORD_" + sfx); v != "" {
			cam.Password = v
		}
		if v := strings.TrimSpace(os.Getenv("IPC_PASSWORD_FILE_" + sfx)); v != "" {
			if pw, err := readFirstLineFile(v); err == nil {
				cam.Password = pw
			}
		}
		_ = applyEnvPort("IPC_HTTP_PORT_"+sfx, &cam.HTTPPort)
		_ = applyEnvPort("IPC_RTSP_PORT_"+sfx, &cam.RTSPPort)
		_ = applyEnvPort("IPC_ONVIF_PORT_"+sfx, &cam.ONVIFPort)
		if v := strings.TrimSpace(os.Getenv("IPC_SSH_" + sfx)); v != "" {
			if err := applyProxy(&cam, EnsureSSHProxyPrefix(v)); err != nil {
				cam.Proxy = EnsureSSHProxyPrefix(v)
			}
		}
		if v := strings.TrimSpace(os.Getenv("IPC_PROXY_" + sfx)); v != "" {
			if err := applyProxy(&cam, v); err != nil {
				cam.Proxy = v
			}
		}
		st.Cameras[name] = cam
	}
}

func findMatchingProfile(cams map[string]Settings, envSuffix string) string {
	for existing := range cams {
		if profileNameToEnvSuffix(existing) == envSuffix {
			return existing
		}
	}
	return envKeyToProfileName(envSuffix)
}

func (st Store) Summaries() []CameraSummary {
	names := make([]string, 0, len(st.Cameras))
	for k := range st.Cameras {
		names = append(names, k)
	}
	sort.Strings(names)
	out := make([]CameraSummary, 0, len(names))
	for _, n := range names {
		c := st.Cameras[n]
		out = append(out, CameraSummary{
			Name:        n,
			Default:     n == st.DefaultCamera,
			Scheme:      c.Scheme,
			Host:        c.Host,
			HTTPPort:    c.HTTPPort,
			RTSPPort:    c.RTSPPort,
			ONVIFPort:   c.ONVIFPort,
			User:        c.User,
			HasPassword: c.Password != "",
			Proxy:       c.RedactedProxy(),
		})
	}
	return out
}

// Resolve selects a named camera profile (or default) from Store and layers global env/flag overrides.
func Load(ov Overrides) (Settings, error) {
	st, err := LoadStore()
	if err != nil {
		return Settings{}, err
	}

	targetName := strings.TrimSpace(ov.Camera)
	if targetName == "" {
		targetName = strings.TrimSpace(os.Getenv("IPC_CAMERA"))
	}

	s := Settings{
		Scheme:    DefaultScheme,
		HTTPPort:  DefaultHTTPPort,
		RTSPPort:  DefaultRTSPPort,
		ONVIFPort: DefaultONVIFPort,
		User:      DefaultUser,
		MediaDir:  st.MediaDir,
	}

	if targetName != "" {
		cam, ok := st.Cameras[targetName]
		if !ok {
			available := make([]string, 0, len(st.Cameras))
			for k := range st.Cameras {
				available = append(available, k)
			}
			sort.Strings(available)
			if len(available) == 0 {
				return s, fmt.Errorf("camera %q not found (no cameras configured)", targetName)
			}
			return s, fmt.Errorf("camera %q not found (available: %s)", targetName, strings.Join(available, ", "))
		}
		applySaved(&s, cam)
		s.Name = targetName
	} else if st.DefaultCamera != "" {
		if cam, ok := st.Cameras[st.DefaultCamera]; ok {
			_, ovHost, _, _ := ParseHostInput(ov.Host)
			if ovHost == "" || strings.EqualFold(ovHost, cam.Host) {
				applySaved(&s, cam)
				s.Name = st.DefaultCamera
			}
		}
	} else if len(st.Cameras) > 1 && strings.TrimSpace(ov.Host) == "" && strings.TrimSpace(os.Getenv("IPC_HOST")) == "" {
		names := make([]string, 0, len(st.Cameras))
		for k := range st.Cameras {
			names = append(names, k)
		}
		sort.Strings(names)
		return s, fmt.Errorf("multiple cameras configured (%s); specify -c/--camera <name> or set a default with `tp-ipc camera use <name>`", strings.Join(names, ", "))
	}

	// Global single-target env vars override only when not explicitly switching to another named profile (unless profile lacks them)
	if targetName == "" || s.Host == "" {
		if v := strings.TrimSpace(os.Getenv("IPC_HOST")); v != "" {
			if err := applyHost(&s, v); err != nil {
				return s, err
			}
		}
	}
	if v := strings.TrimSpace(os.Getenv("IPC_USER")); v != "" && (targetName == "" || s.User == "" || s.User == DefaultUser) {
		s.User = v
	}
	if v := os.Getenv("IPC_PASSWORD"); v != "" && (targetName == "" || s.Password == "") {
		s.Password = v
	}
	if v := strings.TrimSpace(os.Getenv("IPC_PASSWORD_FILE")); v != "" && (targetName == "" || s.Password == "") {
		pw, err := readFirstLineFile(v)
		if err != nil {
			return s, err
		}
		s.Password = pw
	}
	if err := applyEnvPort("IPC_HTTP_PORT", &s.HTTPPort); err != nil {
		return s, err
	}
	if err := applyEnvPort("IPC_RTSP_PORT", &s.RTSPPort); err != nil {
		return s, err
	}
	if err := applyEnvPort("IPC_ONVIF_PORT", &s.ONVIFPort); err != nil {
		return s, err
	}
	if v := strings.TrimSpace(os.Getenv("IPC_SSH")); v != "" && (targetName == "" || s.Proxy == "") {
		if err := applyProxy(&s, EnsureSSHProxyPrefix(v)); err != nil {
			return s, err
		}
	}
	if v := strings.TrimSpace(os.Getenv("IPC_PROXY")); v != "" && (targetName == "" || s.Proxy == "") {
		if err := applyProxy(&s, v); err != nil {
			return s, err
		}
	}

	if strings.TrimSpace(ov.Host) != "" {
		if err := applyHost(&s, ov.Host); err != nil {
			return s, err
		}
	}
	if strings.TrimSpace(ov.User) != "" {
		s.User = strings.TrimSpace(ov.User)
	}
	if ov.HTTPPort > 0 {
		s.HTTPPort = ov.HTTPPort
	}
	if ov.RTSPPort > 0 {
		s.RTSPPort = ov.RTSPPort
	}
	if ov.ONVIFPort > 0 {
		s.ONVIFPort = ov.ONVIFPort
	}
	if strings.TrimSpace(ov.Proxy) != "" {
		if err := applyProxy(&s, ov.Proxy); err != nil {
			return s, err
		}
	}
	if strings.TrimSpace(ov.PasswordFile) != "" {
		pw, err := readFirstLineFile(ov.PasswordFile)
		if err != nil {
			return s, err
		}
		s.Password = pw
	}
	if ov.PasswordStdin {
		in := ov.Stdin
		if in == nil {
			in = os.Stdin
		}
		pw, err := readLine(in)
		if err != nil {
			return s, fmt.Errorf("reading password from stdin: %w", err)
		}
		s.Password = pw
	}

	return normalizeSettings(s, s.Name, st.MediaDir), nil
}

// LoadForConfigure resolves initial settings for `tp-ipc configure` / `tp-ipc camera add`.
// Unlike Load, adding a new named profile never inherits host, user, ports, or password
// from an unrelated default camera, and re-configuring an existing profile requires
// either an explicit password flag/env var or interactive password entry.
func LoadForConfigure(ov Overrides) (Settings, error) {
	st, err := LoadStore()
	if err != nil {
		// If config file already exists on disk and is unreadable/insecure, surface the error.
		if path, pErr := ConfigPath(); pErr == nil {
			if _, statErr := os.Lstat(path); statErr == nil {
				return Settings{}, err
			}
		}
		st = Store{Cameras: make(map[string]Settings)}
	}

	targetName := strings.TrimSpace(ov.Camera)
	if targetName != "" {
		if err := ValidateProfileName(targetName); err != nil {
			return Settings{}, err
		}
	}

	s := Settings{
		Name:      targetName,
		Scheme:    DefaultScheme,
		HTTPPort:  DefaultHTTPPort,
		RTSPPort:  DefaultRTSPPort,
		ONVIFPort: DefaultONVIFPort,
		User:      DefaultUser,
		MediaDir:  st.MediaDir,
	}

	copyConnDefaults := func(saved Settings) {
		savedNoPw := saved
		savedNoPw.Password = ""
		applySaved(&s, savedNoPw)
	}

	if targetName != "" {
		if existing, ok := st.Cameras[targetName]; ok {
			copyConnDefaults(existing)
		}
		if sfx := profileNameToEnvSuffix(targetName); sfx != "" {
			if v := strings.TrimSpace(os.Getenv("IPC_HOST_" + sfx)); v != "" {
				if err := applyHost(&s, v); err != nil {
					return s, err
				}
			}
			if v := strings.TrimSpace(os.Getenv("IPC_USER_" + sfx)); v != "" {
				s.User = v
			}
			if v := os.Getenv("IPC_PASSWORD_" + sfx); v != "" {
				s.Password = v
			}
			if v := strings.TrimSpace(os.Getenv("IPC_PASSWORD_FILE_" + sfx)); v != "" {
				pw, err := readFirstLineFile(v)
				if err != nil {
					return s, err
				}
				s.Password = pw
			}
			if err := applyEnvPort("IPC_HTTP_PORT_"+sfx, &s.HTTPPort); err != nil {
				return s, err
			}
			if err := applyEnvPort("IPC_RTSP_PORT_"+sfx, &s.RTSPPort); err != nil {
				return s, err
			}
			if err := applyEnvPort("IPC_ONVIF_PORT_"+sfx, &s.ONVIFPort); err != nil {
				return s, err
			}
			if v := strings.TrimSpace(os.Getenv("IPC_SSH_" + sfx)); v != "" {
				if err := applyProxy(&s, EnsureSSHProxyPrefix(v)); err != nil {
					return s, err
				}
			}
			if v := strings.TrimSpace(os.Getenv("IPC_PROXY_" + sfx)); v != "" {
				if err := applyProxy(&s, v); err != nil {
					return s, err
				}
			}
		}
	} else {
		if defEnv := strings.TrimSpace(os.Getenv("IPC_CAMERA")); defEnv != "" {
			if existing, ok := st.Cameras[defEnv]; ok {
				copyConnDefaults(existing)
				s.Name = defEnv
			}
		} else if st.DefaultCamera != "" {
			if existing, ok := st.Cameras[st.DefaultCamera]; ok {
				copyConnDefaults(existing)
			}
		}
	}

	if targetName == "" || s.Host == "" {
		if v := strings.TrimSpace(os.Getenv("IPC_HOST")); v != "" {
			if err := applyHost(&s, v); err != nil {
				return s, err
			}
		}
	}
	if v := strings.TrimSpace(os.Getenv("IPC_USER")); v != "" && (targetName == "" || s.User == "" || s.User == DefaultUser) {
		s.User = v
	}
	if v := os.Getenv("IPC_PASSWORD"); v != "" && s.Password == "" {
		s.Password = v
	}
	if v := strings.TrimSpace(os.Getenv("IPC_PASSWORD_FILE")); v != "" && s.Password == "" {
		pw, err := readFirstLineFile(v)
		if err != nil {
			return s, err
		}
		s.Password = pw
	}
	if err := applyEnvPort("IPC_HTTP_PORT", &s.HTTPPort); err != nil {
		return s, err
	}
	if err := applyEnvPort("IPC_RTSP_PORT", &s.RTSPPort); err != nil {
		return s, err
	}
	if err := applyEnvPort("IPC_ONVIF_PORT", &s.ONVIFPort); err != nil {
		return s, err
	}
	if v := strings.TrimSpace(os.Getenv("IPC_SSH")); v != "" && (targetName == "" || s.Proxy == "") {
		if err := applyProxy(&s, EnsureSSHProxyPrefix(v)); err != nil {
			return s, err
		}
	}
	if v := strings.TrimSpace(os.Getenv("IPC_PROXY")); v != "" && (targetName == "" || s.Proxy == "") {
		if err := applyProxy(&s, v); err != nil {
			return s, err
		}
	}

	if strings.TrimSpace(ov.Host) != "" {
		if err := applyHost(&s, ov.Host); err != nil {
			return s, err
		}
	}
	if strings.TrimSpace(ov.User) != "" {
		s.User = strings.TrimSpace(ov.User)
	}
	if ov.HTTPPort > 0 {
		s.HTTPPort = ov.HTTPPort
	}
	if ov.RTSPPort > 0 {
		s.RTSPPort = ov.RTSPPort
	}
	if ov.ONVIFPort > 0 {
		s.ONVIFPort = ov.ONVIFPort
	}
	if strings.TrimSpace(ov.Proxy) != "" {
		if err := applyProxy(&s, ov.Proxy); err != nil {
			return s, err
		}
	}
	if strings.TrimSpace(ov.PasswordFile) != "" {
		pw, err := readFirstLineFile(ov.PasswordFile)
		if err != nil {
			return s, err
		}
		s.Password = pw
	}
	if ov.PasswordStdin {
		in := ov.Stdin
		if in == nil {
			in = os.Stdin
		}
		pw, err := readLine(in)
		if err != nil {
			return s, fmt.Errorf("reading password from stdin: %w", err)
		}
		s.Password = pw
	}

	return normalizeSettings(s, s.Name, st.MediaDir), nil
}

// SaveStore writes the multi-camera Store atomically with 0600 permissions.
func SaveStore(st Store) (string, error) {
	for k := range st.Cameras {
		if err := ValidateProfileName(k); err != nil {
			return "", err
		}
	}
	if st.DefaultCamera != "" {
		if err := ValidateProfileName(st.DefaultCamera); err != nil {
			return "", err
		}
	}
	path, err := ConfigPath()
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create config dir: %w", err)
	}
	_ = os.Chmod(dir, 0o700)

	// Clear legacy flat fields before persisting
	st.Scheme, st.Host, st.User, st.Password, st.Proxy = "", "", "", "", ""
	st.HTTPPort, st.RTSPPort, st.ONVIFPort = 0, 0, 0

	tmp, err := os.CreateTemp(dir, ".config-*.json")
	if err != nil {
		return "", fmt.Errorf("create temp config: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return "", fmt.Errorf("chmod temp config: %w", err)
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		cleanup()
		return "", err
	}
	data = append(data, '\n')
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return "", fmt.Errorf("write config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return "", fmt.Errorf("sync config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("close config: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("save config: %w", err)
	}
	return path, nil
}

// Save upserts a camera profile into the config file (defaulting profile name to s.Name or "default").
func Save(s Settings, setDefault bool) (string, error) {
	profile := strings.TrimSpace(s.Name)
	if profile == "" {
		profile = "default"
	}
	if err := ValidateProfileName(profile); err != nil {
		return "", err
	}
	st, err := LoadStore()
	if err != nil {
		// Allow overwriting/creating fresh if no file exists; fail if existing file is corrupt/insecure
		if path, pErr := ConfigPath(); pErr == nil {
			if _, statErr := os.Lstat(path); statErr == nil {
				return "", err
			}
		}
		st = Store{Cameras: make(map[string]Settings)}
	}
	if st.Cameras == nil {
		st.Cameras = make(map[string]Settings)
	}
	s.Name = profile
	st.Cameras[profile] = s
	if setDefault || st.DefaultCamera == "" || len(st.Cameras) == 1 {
		st.DefaultCamera = profile
	}
	return SaveStore(st)
}

func (s Settings) HTTPBaseURL() string {
	defaultPort := (s.Scheme == "http" && s.HTTPPort == 80) || (s.Scheme == "https" && s.HTTPPort == 443)
	hostPart := s.Host
	if strings.Contains(hostPart, ":") && !strings.HasPrefix(hostPart, "[") {
		hostPart = "[" + hostPart + "]"
	}
	if defaultPort {
		return fmt.Sprintf("%s://%s", s.Scheme, hostPart)
	}
	return fmt.Sprintf("%s://%s", s.Scheme, net.JoinHostPort(s.Host, strconv.Itoa(s.HTTPPort)))
}

func (s Settings) ONVIFBaseURL() string {
	return fmt.Sprintf("http://%s", net.JoinHostPort(s.Host, strconv.Itoa(s.ONVIFPort)))
}

func (s Settings) RTSPURL(stream string, redacted bool) string {
	pw := s.Password
	if redacted {
		pw = "****"
	} else {
		pw = url.PathEscape(pw)
	}
	u := url.PathEscape(s.User)
	return fmt.Sprintf("rtsp://%s:%s@%s/%s", u, pw, net.JoinHostPort(s.Host, strconv.Itoa(s.RTSPPort)), strings.TrimPrefix(stream, "/"))
}

// Redact scrubs password, URL-escaped password, Basic auth tokens, and stok values from text.
func (s Settings) Redact(text string, extraSecrets ...string) string {
	if text == "" {
		return text
	}
	candidates := make([]string, 0, 6+len(extraSecrets))
	if s.Password != "" {
		candidates = append(candidates,
			s.Password,
			url.QueryEscape(s.Password),
			url.PathEscape(s.Password),
			base64.StdEncoding.EncodeToString([]byte(s.User+":"+s.Password)),
		)
	}
	if pSpec, err := ParseProxyInput(s.Proxy); err == nil && pSpec.Password != "" {
		candidates = append(candidates,
			pSpec.Password,
			url.QueryEscape(pSpec.Password),
			url.PathEscape(pSpec.Password),
			base64.StdEncoding.EncodeToString([]byte(pSpec.User+":"+pSpec.Password)),
		)
	}
	for _, ex := range extraSecrets {
		if ex != "" {
			candidates = append(candidates, ex, url.QueryEscape(ex), url.PathEscape(ex))
		}
	}
	out := text
	for _, secret := range candidates {
		if secret != "" {
			out = strings.ReplaceAll(out, secret, "***")
		}
	}
	return out
}

func applySaved(dst *Settings, saved Settings) {
	if saved.Host != "" {
		_ = applyHost(dst, saved.Host)
	}
	if saved.Scheme != "" {
		dst.Scheme = saved.Scheme
	}
	if saved.HTTPPort > 0 {
		dst.HTTPPort = saved.HTTPPort
	}
	if saved.RTSPPort > 0 {
		dst.RTSPPort = saved.RTSPPort
	}
	if saved.ONVIFPort > 0 {
		dst.ONVIFPort = saved.ONVIFPort
	}
	if saved.User != "" {
		dst.User = saved.User
	}
	if saved.Password != "" {
		dst.Password = saved.Password
	}
	if saved.Proxy != "" {
		if err := applyProxy(dst, saved.Proxy); err != nil {
			dst.Proxy = saved.Proxy
		}
	}
	if saved.MediaDir != "" {
		dst.MediaDir = saved.MediaDir
	}
}

func applyProxy(dst *Settings, raw string) error {
	spec, err := ParseProxyInput(raw)
	if err != nil {
		return err
	}
	if spec.DirectOverride {
		dst.Proxy = ""
		return nil
	}
	if spec.Kind != "" {
		dst.Proxy = spec.Canonical()
	}
	return nil
}

func applyHost(dst *Settings, raw string) error {
	scheme, host, port, err := ParseHostInput(raw)
	if err != nil {
		return err
	}
	dst.Scheme = scheme
	dst.Host = host
	if port > 0 {
		dst.HTTPPort = port
	} else if scheme == "https" && dst.HTTPPort == DefaultHTTPPort {
		dst.HTTPPort = 443
	} else if scheme == "http" && dst.HTTPPort == 443 {
		dst.HTTPPort = DefaultHTTPPort
	}
	return nil
}

func applyEnvPort(envName string, dst *int) error {
	v := strings.TrimSpace(os.Getenv(envName))
	if v == "" {
		return nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid %s=%q (must be 1..65535)", envName, v)
	}
	*dst = n
	return nil
}

func readFirstLineFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open password file %s: %w", path, err)
	}
	defer f.Close()
	return readLine(f)
}

func readLine(r io.Reader) (string, error) {
	scanner := bufio.NewScanner(r)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", err
		}
		return "", errors.New("empty password input")
	}
	pw := strings.TrimRight(scanner.Text(), "\r\n")
	if pw == "" {
		return "", errors.New("empty password input")
	}
	return pw, nil
}
