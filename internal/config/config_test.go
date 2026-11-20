package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMultiCameraStoreAndIndexedEnv(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	// Save two named profiles
	_, err := Save(Settings{
		Name:     "desk",
		Host:     "192.168.1.60",
		User:     "admin",
		Password: "p1",
	}, true)
	if err != nil {
		t.Fatalf("Save desk: %v", err)
	}
	_, err = Save(Settings{
		Name:     "door",
		Host:     "192.168.1.61",
		User:     "admin",
		Password: "p2",
	}, false)
	if err != nil {
		t.Fatalf("Save door: %v", err)
	}

	// Default camera should be "desk"
	defCfg, err := Load(Overrides{})
	if err != nil {
		t.Fatalf("Load default: %v", err)
	}
	if defCfg.Name != "desk" || defCfg.Host != "192.168.1.60" || defCfg.Password != "p1" {
		t.Fatalf("unexpected default settings: %+v", defCfg)
	}

	// Select "door" explicitly + override password via IPC_PASSWORD_DOOR
	t.Setenv("IPC_PASSWORD_DOOR", "env_injected_door_pw")
	doorCfg, err := Load(Overrides{Camera: "door"})
	if err != nil {
		t.Fatalf("Load door: %v", err)
	}
	if doorCfg.Name != "door" || doorCfg.Host != "192.168.1.61" || doorCfg.Password != "env_injected_door_pw" {
		t.Fatalf("unexpected door settings: %+v", doorCfg)
	}

	// Pure env-defined camera via IPC_HOST_GARAGE + IPC_PASSWORD_GARAGE (no file entry needed)
	t.Setenv("IPC_HOST_GARAGE", "http://192.168.1.62:8080")
	t.Setenv("IPC_PASSWORD_GARAGE", "garage_pw")
	garageCfg, err := Load(Overrides{Camera: "garage"})
	if err != nil {
		t.Fatalf("Load garage: %v", err)
	}
	if garageCfg.Host != "192.168.1.62" || garageCfg.HTTPPort != 8080 || garageCfg.Password != "garage_pw" {
		t.Fatalf("unexpected garage settings: %+v", garageCfg)
	}

	// Legacy single-camera flat config.json backward compatibility
	legacyDir := filepath.Join(tmp, "legacy")
	t.Setenv("XDG_CONFIG_HOME", legacyDir)
	cfgDir := filepath.Join(legacyDir, "tp-ipc")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	legacyJSON := []byte(`{"host":"192.168.1.99","user":"admin","password":"old"}`)
	if err := os.WriteFile(filepath.Join(cfgDir, "config.json"), legacyJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	legCfg, err := Load(Overrides{})
	if err != nil {
		t.Fatalf("Load legacy: %v", err)
	}
	if legCfg.Host != "192.168.1.99" || legCfg.Password != "old" {
		t.Fatalf("unexpected legacy settings: %+v", legCfg)
	}
}

func TestProfileNameValidationAndSanitization(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	badNames := []string{"", "../escape", "/../../outside", "a/b", `a\b`, ".hidden", "-dash", "foo..bar"}
	for _, bad := range badNames {
		if bad != "" {
			if err := ValidateProfileName(bad); err == nil {
				t.Fatalf("expected profile name %q to be rejected", bad)
			}
			if _, err := Save(Settings{Name: bad, Host: "10.0.0.1"}, false); err == nil {
				t.Fatalf("expected Save(%q) to fail", bad)
			}
		}
	}

	goodNames := []string{"desk", "cam-01", "office_2", "lab.cam1"}
	for _, good := range goodNames {
		if err := ValidateProfileName(good); err != nil {
			t.Fatalf("expected profile name %q to be valid, got %v", good, err)
		}
	}

	if got := SanitizeProfileToken("/../../outside_cam-1"); got != "outside_cam-1" {
		t.Fatalf("unexpected sanitized token %q", got)
	}
}

func TestLoadForConfigureDoesNotLeakDefaultProfile(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	// Save an existing default camera with custom ports, user, and password
	_, err := Save(Settings{
		Name:     "desk",
		Host:     "10.100.20.50",
		HTTPPort: 8080,
		User:     "desk_admin",
		Password: "desk_secret_password",
	}, true)
	if err != nil {
		t.Fatalf("Save desk: %v", err)
	}

	// Adding a brand-new named profile ("dogee") must NOT inherit desk's password, user, or port
	dogeeCfg, err := LoadForConfigure(Overrides{
		Camera: "dogee",
		Host:   "10.100.20.60",
	})
	if err != nil {
		t.Fatalf("LoadForConfigure dogee: %v", err)
	}
	if dogeeCfg.Host != "10.100.20.60" || dogeeCfg.HTTPPort != 80 || dogeeCfg.User != "admin" || dogeeCfg.Password != "" {
		t.Fatalf("LoadForConfigure leaked default profile settings into new profile: %+v", dogeeCfg)
	}

	// Indexed env var IPC_PASSWORD_DOGEE should work even before "dogee" exists in config.json
	t.Setenv("IPC_PASSWORD_DOGEE", "dogee_env_pw")
	dogeeWithEnv, err := LoadForConfigure(Overrides{
		Camera: "dogee",
		Host:   "https://10.100.20.60",
	})
	if err != nil {
		t.Fatalf("LoadForConfigure dogee with env: %v", err)
	}
	if dogeeWithEnv.Scheme != "https" || dogeeWithEnv.HTTPPort != 443 || dogeeWithEnv.Password != "dogee_env_pw" {
		t.Fatalf("unexpected dogee env/https settings: %+v", dogeeWithEnv)
	}
}

func TestProxyParsingSecurityAndOverrides(t *testing.T) {
	// 1. Bare SSH alias, user@host:port, ssh://, socks5://, http://, direct
	s1, err := ParseProxyInput("home-nas")
	if err != nil || s1.Kind != "ssh" || s1.SSHTarget != "home-nas" || s1.Port != 0 || s1.Canonical() != "ssh://home-nas" {
		t.Fatalf("unexpected bare SSH parse: %+v err=%v", s1, err)
	}

	s2, err := ParseProxyInput("ubuntu@203.0.113.5:2222")
	if err != nil || s2.Kind != "ssh" || s2.SSHTarget != "ubuntu@203.0.113.5" || s2.Port != 2222 || s2.Canonical() != "ssh://ubuntu@203.0.113.5:2222" {
		t.Fatalf("unexpected user@host:port parse: %+v err=%v", s2, err)
	}

	s3, err := ParseProxyInput("socks5://puser:psecret@127.0.0.1:1080")
	if err != nil || s3.Kind != "socks5" || s3.Port != 1080 || s3.User != "puser" || s3.Password != "psecret" {
		t.Fatalf("unexpected socks5 parse: %+v err=%v", s3, err)
	}
	if strings.Contains(s3.Redacted(), "psecret") {
		t.Fatalf("Redacted leaked proxy password: %s", s3.Redacted())
	}

	// 2. Reject SSH option injection & invalid inputs
	badProxies := []string{
		"-oProxyCommand=evil",
		"-oLocalCommand=id@host",
		"user@-badhost",
		"ssh://-oProxyCommand=evil",
		"ssh://user:pass@host",
		"ssh://host/extra-path",
		"ftp://127.0.0.1:21",
		"host with spaces",
	}
	for _, bad := range badProxies {
		if _, err := ParseProxyInput(bad); err == nil {
			t.Fatalf("expected ParseProxyInput(%q) to fail", bad)
		}
	}

	// 3. Profile persistence + "--proxy direct" override + Redact
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)
	if _, err := Save(Settings{
		Name:     "remote-cam",
		Host:     "10.100.20.60",
		User:     "admin",
		Password: "cam_pw",
		Proxy:    "home-box",
	}, true); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(Overrides{})
	if err != nil || loaded.Proxy != "ssh://home-box" {
		t.Fatalf("expected saved ssh://home-box proxy, got %+v err=%v", loaded, err)
	}

	directCfg, err := Load(Overrides{Proxy: "direct"})
	if err != nil || directCfg.Proxy != "" {
		t.Fatalf("expected --proxy direct to clear saved proxy, got %+v err=%v", directCfg, err)
	}

	t.Setenv("IPC_CAMERAS", `{"badcam":{"host":"10.100.20.61","proxy":"-oProxyCommand=evil"}}`)
	if _, err := LoadStore(); err == nil {
		t.Fatal("expected invalid proxy in IPC_CAMERAS to fail LoadStore")
	}
}
