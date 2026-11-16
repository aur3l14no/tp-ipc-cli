package config

import (
	"os"
	"path/filepath"
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
