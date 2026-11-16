package mcp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aur3l14no/tp-ipc-cli/internal/config"
)

func startMockCamera(t *testing.T, model, alias string, failFirstDS bool) *httptest.Server {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa generate: %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal spki: %v", err)
	}
	keyB64 := base64.StdEncoding.EncodeToString(spki)

	var dsCalls atomic.Int32
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/pc/Content.htm":
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error_code": -40401,
				"data": map[string]any{
					"code":         -40407,
					"key":          keyB64,
					"nonce":        "n123",
					"encrypt_type": []string{"1", "2"},
				},
			})
		case r.URL.Path == "/":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error_code": 0,
				"stok":       "tok_fresh_" + alias,
			})
		case strings.HasSuffix(r.URL.Path, "/ds"):
			n := dsCalls.Add(1)
			if failFirstDS && n == 1 {
				_ = json.NewEncoder(w).Encode(map[string]any{"error_code": -40401})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error_code": 0,
				"device_info": map[string]any{
					"basic_info": map[string]any{
						"device_model": model,
						"hw_version":   "5.0",
						"sw_version":   "1.0.3%20Build%20260119",
						"device_alias": alias,
					},
				},
				"function": map[string]any{
					"module_spec": map[string]any{
						"ptz":             "1",
						"smart_detection": "1",
						"target_track":    "1",
						"lens_mask":       "1",
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestMCPMultiCameraRoutingAndSessionRelogin(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	camA := startMockCamera(t, "TL-IPC48AW", "DeskCam", true)
	defer camA.Close()
	camB := startMockCamera(t, "TL-IPC45AW", "DoorCam", false)
	defer camB.Close()

	t.Setenv("IPC_HOST_DESK", camA.URL)
	t.Setenv("IPC_PASSWORD_DESK", "pw_a")
	t.Setenv("IPC_HOST_DOOR", camB.URL)
	t.Setenv("IPC_PASSWORD_DOOR", "pw_b")
	t.Setenv("IPC_CAMERA", "desk")

	srv := NewServer(config.Overrides{})

	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"camera_list","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"camera_info","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"camera_info","arguments":{"camera":"door"}}}`,
	}, "\n") + "\n"

	var out bytes.Buffer
	if err := srv.Serve(context.Background(), strings.NewReader(input), &out); err != nil {
		t.Fatalf("Serve failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("expected 4 JSON-RPC responses, got %d:\n%s", len(lines), out.String())
	}
	if !strings.Contains(lines[1], `\"desk\"`) || !strings.Contains(lines[1], `\"door\"`) {
		t.Fatalf("camera_list missing profiles: %s", lines[1])
	}
	if !strings.Contains(lines[2], "DeskCam") || !strings.Contains(lines[2], "TL-IPC48AW") {
		t.Fatalf("default camera_info should hit DeskCam: %s", lines[2])
	}
	if !strings.Contains(lines[3], "DoorCam") || !strings.Contains(lines[3], "TL-IPC45AW") {
		t.Fatalf("explicit camera=door should hit DoorCam: %s", lines[3])
	}
}

func TestMCPIdleServeRespectsCancellation(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()

	ctx, cancel := context.WithCancel(context.Background())
	srv := NewServer(config.Overrides{})
	errCh := make(chan error, 1)
	go func() {
		var out bytes.Buffer
		errCh <- srv.Serve(ctx, pr, &out)
	}()

	time.Sleep(25 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(400 * time.Millisecond):
		t.Fatal("Serve blocked on idle stdin after context cancellation")
	}
}

func TestMCPHostOverrideDoesNotPoisonNamedProfileCache(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	deskCam := startMockCamera(t, "TL-IPC48AW", "StoredDesk", false)
	defer deskCam.Close()
	overrideCam := startMockCamera(t, "TL-IPC45AW", "OverriddenHost", false)
	defer overrideCam.Close()

	t.Setenv("IPC_HOST_DESK", deskCam.URL)
	t.Setenv("IPC_PASSWORD_DESK", "pw_desk")
	t.Setenv("IPC_CAMERA", "desk")

	// Order 1: default (with --host override) first, then explicit camera="desk"
	srv1 := NewServer(config.Overrides{Host: overrideCam.URL})
	in1 := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"camera_info","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"camera_info","arguments":{"camera":"desk"}}}`,
	}, "\n") + "\n"
	var out1 bytes.Buffer
	if err := srv1.Serve(context.Background(), strings.NewReader(in1), &out1); err != nil {
		t.Fatalf("srv1.Serve failed: %v", err)
	}
	lines1 := strings.Split(strings.TrimSpace(out1.String()), "\n")
	if len(lines1) != 2 || !strings.Contains(lines1[0], "OverriddenHost") || !strings.Contains(lines1[1], "StoredDesk") {
		t.Fatalf("unexpected Order 1 routing:\n%s", out1.String())
	}

	// Order 2: explicit camera="desk" first, then default (with --host override)
	srv2 := NewServer(config.Overrides{Host: overrideCam.URL})
	in2 := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"camera_info","arguments":{"camera":"desk"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"camera_info","arguments":{}}}`,
	}, "\n") + "\n"
	var out2 bytes.Buffer
	if err := srv2.Serve(context.Background(), strings.NewReader(in2), &out2); err != nil {
		t.Fatalf("srv2.Serve failed: %v", err)
	}
	lines2 := strings.Split(strings.TrimSpace(out2.String()), "\n")
	if len(lines2) != 2 || !strings.Contains(lines2[0], "StoredDesk") || !strings.Contains(lines2[1], "OverriddenHost") {
		t.Fatalf("unexpected Order 2 routing:\n%s", out2.String())
	}
}
