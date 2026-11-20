package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ProxySpec describes a normalized proxy or SSH jump host used to reach a camera.
type ProxySpec struct {
	Kind           string // "", "ssh", "socks5", "http", "https"
	DirectOverride bool   // true when input was "direct" or "none"
	SSHTarget      string // "host" or "user@host" for Kind == "ssh"
	Host           string
	Port           int // 0 for SSH when omitted (preserves ~/.ssh/config Port)
	User           string
	Password       string
}

// Canonical returns the normalized string form persisted in config files (e.g. "ssh://home-nas").
func (p ProxySpec) Canonical() string {
	switch p.Kind {
	case "":
		return ""
	case "ssh":
		hostPart := p.Host
		if strings.Contains(hostPart, ":") && !strings.HasPrefix(hostPart, "[") {
			hostPart = "[" + hostPart + "]"
		}
		if p.Port > 0 {
			hostPart = net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
		}
		if p.User != "" {
			return "ssh://" + p.User + "@" + hostPart
		}
		return "ssh://" + hostPart
	case "socks5", "http", "https":
		u := &url.URL{
			Scheme: p.Kind,
			Host:   net.JoinHostPort(p.Host, strconv.Itoa(p.Port)),
		}
		if p.User != "" || p.Password != "" {
			if p.Password != "" {
				u.User = url.UserPassword(p.User, p.Password)
			} else {
				u.User = url.User(p.User)
			}
		}
		return u.String()
	default:
		return ""
	}
}

// Redacted returns a display-safe proxy string with any embedded proxy password masked.
func (p ProxySpec) Redacted() string {
	if p.Kind == "" {
		return ""
	}
	if p.Kind == "ssh" || p.Password == "" {
		return p.Canonical()
	}
	hostPort := net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
	return fmt.Sprintf("%s://%s:****@%s", p.Kind, url.PathEscape(p.User), hostPort)
}

// EnsureSSHProxyPrefix interprets a --ssh / IPC_SSH value as an SSH host unless "direct"/"none" is given.
func EnsureSSHProxyPrefix(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || strings.EqualFold(trimmed, "direct") || strings.EqualFold(trimmed, "none") {
		return trimmed
	}
	if strings.HasPrefix(strings.ToLower(trimmed), "ssh://") {
		return trimmed
	}
	return "ssh://" + trimmed
}

// ParseProxyInput parses an SSH host ("home-nas", "user@host:2222", "ssh://user@host:2222"),
// SOCKS5 URL ("socks5://127.0.0.1:1080"), HTTP CONNECT URL ("http://127.0.0.1:8080"), or "direct"/"none".
func ParseProxyInput(raw string) (ProxySpec, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ProxySpec{}, nil
	}
	if strings.EqualFold(trimmed, "direct") || strings.EqualFold(trimmed, "none") {
		return ProxySpec{DirectOverride: true}, nil
	}

	if !strings.Contains(trimmed, "://") {
		return parseBareSSHProxy(trimmed)
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return ProxySpec{}, fmt.Errorf("invalid proxy %q: %w", raw, err)
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return ProxySpec{}, fmt.Errorf("invalid proxy %q (unexpected path, query, or fragment)", raw)
	}

	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "ssh":
		if u.User != nil {
			if _, hasPw := u.User.Password(); hasPw {
				return ProxySpec{}, errors.New("SSH proxy uses SSH keys/agent/ssh_config; do not embed passwords in ssh:// URLs")
			}
		}
		var user string
		if u.User != nil {
			user = u.User.Username()
		}
		host := u.Hostname()
		if host == "" {
			return ProxySpec{}, fmt.Errorf("missing SSH host in %q", raw)
		}
		port := 0
		if pStr := u.Port(); pStr != "" {
			p, convErr := strconv.Atoi(pStr)
			if convErr != nil || p < 1 || p > 65535 {
				return ProxySpec{}, fmt.Errorf("invalid SSH port %q in %q", pStr, raw)
			}
			port = p
		}
		return buildValidatedSSHSpec(user, host, port)

	case "socks5", "socks5h":
		host := u.Hostname()
		if host == "" {
			return ProxySpec{}, fmt.Errorf("missing SOCKS5 host in %q", raw)
		}
		port := 1080
		if pStr := u.Port(); pStr != "" {
			p, convErr := strconv.Atoi(pStr)
			if convErr != nil || p < 1 || p > 65535 {
				return ProxySpec{}, fmt.Errorf("invalid SOCKS5 port %q in %q", pStr, raw)
			}
			port = p
		}
		var user, pw string
		if u.User != nil {
			user = u.User.Username()
			pw, _ = u.User.Password()
		}
		return ProxySpec{
			Kind:     "socks5",
			Host:     host,
			Port:     port,
			User:     user,
			Password: pw,
		}, nil

	case "http", "https":
		host := u.Hostname()
		if host == "" {
			return ProxySpec{}, fmt.Errorf("missing HTTP proxy host in %q", raw)
		}
		port := 8080
		if scheme == "https" {
			port = 443
		}
		if pStr := u.Port(); pStr != "" {
			p, convErr := strconv.Atoi(pStr)
			if convErr != nil || p < 1 || p > 65535 {
				return ProxySpec{}, fmt.Errorf("invalid proxy port %q in %q", pStr, raw)
			}
			port = p
		}
		var user, pw string
		if u.User != nil {
			user = u.User.Username()
			pw, _ = u.User.Password()
		}
		return ProxySpec{
			Kind:     scheme,
			Host:     host,
			Port:     port,
			User:     user,
			Password: pw,
		}, nil

	default:
		return ProxySpec{}, fmt.Errorf("unsupported proxy scheme %q (expected ssh host, ssh://, socks5://, http://, or direct)", u.Scheme)
	}
}

func parseBareSSHProxy(trimmed string) (ProxySpec, error) {
	var user string
	hostPort := trimmed
	if at := strings.IndexByte(trimmed, '@'); at >= 0 {
		user = trimmed[:at]
		hostPort = trimmed[at+1:]
		if user == "" || strings.Contains(hostPort, "@") {
			return ProxySpec{}, fmt.Errorf("invalid SSH proxy target %q", trimmed)
		}
	}

	var host string
	port := 0
	if strings.HasPrefix(hostPort, "[") {
		if strings.Contains(hostPort, "]:") {
			h, pStr, err := net.SplitHostPort(hostPort)
			if err != nil {
				return ProxySpec{}, fmt.Errorf("invalid SSH proxy target %q: %w", trimmed, err)
			}
			p, convErr := strconv.Atoi(pStr)
			if convErr != nil || p < 1 || p > 65535 {
				return ProxySpec{}, fmt.Errorf("invalid SSH port %q in %q", pStr, trimmed)
			}
			host, port = h, p
		} else if strings.HasSuffix(hostPort, "]") {
			host = strings.TrimSuffix(strings.TrimPrefix(hostPort, "["), "]")
		} else {
			return ProxySpec{}, fmt.Errorf("invalid bracketed host in %q", trimmed)
		}
	} else if strings.Count(hostPort, ":") == 1 {
		h, pStr, err := net.SplitHostPort(hostPort)
		if err != nil {
			return ProxySpec{}, fmt.Errorf("invalid SSH proxy target %q: %w", trimmed, err)
		}
		p, convErr := strconv.Atoi(pStr)
		if convErr != nil || p < 1 || p > 65535 {
			return ProxySpec{}, fmt.Errorf("invalid SSH port %q in %q", pStr, trimmed)
		}
		host, port = h, p
	} else {
		host = hostPort
	}

	return buildValidatedSSHSpec(user, host, port)
}

func buildValidatedSSHSpec(user, host string, port int) (ProxySpec, error) {
	if err := validateSSHToken(host, "host", true); err != nil {
		return ProxySpec{}, err
	}
	if user != "" {
		if err := validateSSHToken(user, "user", false); err != nil {
			return ProxySpec{}, err
		}
	}
	target := host
	if user != "" {
		target = user + "@" + host
	}
	return ProxySpec{
		Kind:      "ssh",
		SSHTarget: target,
		Host:      host,
		Port:      port,
		User:      user,
	}, nil
}

func validateSSHToken(val, label string, allowColons bool) error {
	if val == "" || len(val) > 253 {
		return fmt.Errorf("invalid SSH %s %q", label, val)
	}
	if strings.HasPrefix(val, "-") {
		return fmt.Errorf("invalid SSH %s %q (must not start with '-')", label, val)
	}
	for i := 0; i < len(val); i++ {
		ch := val[i]
		ok := (ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '.' || ch == '-' || ch == '_' ||
			(allowColons && ch == ':')
		if !ok {
			return fmt.Errorf("invalid character %q in SSH %s %q", ch, label, val)
		}
	}
	return nil
}

// RedactedProxy returns the display-safe form of s.Proxy.
func (s Settings) RedactedProxy() string {
	spec, err := ParseProxyInput(s.Proxy)
	if err != nil {
		return ""
	}
	return spec.Redacted()
}
