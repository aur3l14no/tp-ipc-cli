package ipc

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aur3l14no/tp-ipc-cli/internal/config"
)

// TestHelperFakeSSH acts as a minimal OpenSSH `-D 127.0.0.1:<port>` stand-in when GO_WANT_FAKE_SSH=1.
func TestHelperFakeSSH(t *testing.T) {
	if os.Getenv("GO_WANT_FAKE_SSH") != "1" {
		return
	}

	args := os.Args
	// Find "-D" and record arguments to FAKE_SSH_LOG if set
	if logFile := os.Getenv("FAKE_SSH_LOG"); logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err == nil {
			fmt.Fprintln(f, strings.Join(args, " "))
			_ = f.Close()
		}
	}

	if os.Getenv("FAKE_SSH_FAIL") == "1" {
		fmt.Fprintln(os.Stderr, "Permission denied (publickey).")
		os.Exit(255)
	}

	var bindAddr string
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-D" {
			bindAddr = args[i+1]
			break
		}
	}
	if bindAddr == "" {
		fmt.Fprintln(os.Stderr, "missing -D bind address")
		os.Exit(2)
	}

	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot listen to port: %v\n", err)
		os.Exit(255)
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			os.Exit(0)
		}
		go serveTestSOCKS5Conn(conn, "", "")
	}
}

func serveTestSOCKS5Conn(conn net.Conn, wantUser, wantPass string) {
	defer conn.Close()
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	if wantUser != "" {
		_, _ = conn.Write([]byte{0x05, 0x02})
		var verUlen [2]byte
		if _, err := io.ReadFull(conn, verUlen[:]); err != nil {
			return
		}
		u := make([]byte, int(verUlen[1]))
		if _, err := io.ReadFull(conn, u); err != nil {
			return
		}
		var plen [1]byte
		if _, err := io.ReadFull(conn, plen[:]); err != nil {
			return
		}
		p := make([]byte, int(plen[0]))
		if _, err := io.ReadFull(conn, p); err != nil {
			return
		}
		if string(u) != wantUser || string(p) != wantPass {
			_, _ = conn.Write([]byte{0x01, 0x01})
			return
		}
		_, _ = conn.Write([]byte{0x01, 0x00})
	} else {
		_, _ = conn.Write([]byte{0x05, 0x00})
	}

	var req [4]byte
	if _, err := io.ReadFull(conn, req[:]); err != nil || req[1] != 0x01 {
		return
	}
	var host string
	switch req[3] {
	case 0x01:
		var ip4 [4]byte
		if _, err := io.ReadFull(conn, ip4[:]); err != nil {
			return
		}
		host = net.IP(ip4[:]).String()
	case 0x03:
		var dlen [1]byte
		if _, err := io.ReadFull(conn, dlen[:]); err != nil {
			return
		}
		d := make([]byte, int(dlen[0]))
		if _, err := io.ReadFull(conn, d); err != nil {
			return
		}
		host = string(d)
	case 0x04:
		var ip6 [16]byte
		if _, err := io.ReadFull(conn, ip6[:]); err != nil {
			return
		}
		host = net.IP(ip6[:]).String()
	default:
		return
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(conn, portBytes[:]); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(portBytes[:]))

	upstream, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 3*time.Second)
	if err != nil {
		_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upstream.Close()
	_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0})

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, conn)
		if tc, ok := upstream.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, upstream)
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

func startMockCameraAndRTSP(t *testing.T) (camHost string, httpPort int, rtspPort int, hits *atomic.Int32) {
	t.Helper()
	var reqCount atomic.Int32
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/pc/Content.htm" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error_code": -40401,
				"data":       map[string]any{"code": -40407, "nonce": "n1", "md5_encrypt_type": 1},
			})
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["method"] == "do" {
			_ = json.NewEncoder(w).Encode(map[string]any{"error_code": 0, "stok": "stok_via_proxy"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error_code": 0,
			"device_info": map[string]any{
				"basic_info": map[string]any{
					"device_model": "TL-IPC48AW-PLUS",
					"hw_version":   "5.0",
					"sw_version":   "1.0.3",
					"device_alias": "proxied-cam",
				},
			},
		})
	}))
	t.Cleanup(httpSrv.Close)

	rtspLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rtspLn.Close() })
	go func() {
		for {
			c, aErr := rtspLn.Accept()
			if aErr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				reqCount.Add(1)
				buf := make([]byte, 512)
				n, _ := conn.Read(buf)
				if n > 0 {
					_, _ = conn.Write([]byte("RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: OPTIONS, DESCRIBE, SETUP, PLAY\r\n\r\n"))
				}
			}(c)
		}
	}()

	_, host, hPort, _ := config.ParseHostInput(httpSrv.URL)
	return host, hPort, rtspLn.Addr().(*net.TCPAddr).Port, &reqCount
}

func TestSSHProxyPoolHTTPAndRTSPBridge(t *testing.T) {
	tmp := t.TempDir()
	logFile := filepath.Join(tmp, "ssh_invocations.log")
	wrapper := filepath.Join(tmp, "fake-ssh")
	testBin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf("#!/bin/sh\nexport GO_WANT_FAKE_SSH=1\nexport FAKE_SSH_LOG=%q\nexec %q -test.run=^TestHelperFakeSSH$ -- \"$@\"\n", logFile, testBin)
	if err := os.WriteFile(wrapper, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	globalSSHPool.mu.Lock()
	globalSSHPool.sshBinFixed = wrapper
	globalSSHPool.mu.Unlock()
	t.Cleanup(func() {
		CloseSharedProxies()
		globalSSHPool.mu.Lock()
		globalSSHPool.sshBinFixed = ""
		globalSSHPool.mu.Unlock()
	})

	camHost, httpPort, rtspPort, hits := startMockCameraAndRTSP(t)

	c1, err := NewClient(config.Settings{
		Name:     "cam1",
		Host:     camHost,
		HTTPPort: httpPort,
		RTSPPort: rtspPort,
		User:     "admin",
		Password: "secret_pw",
		Proxy:    "ubuntu@home-nas:2222",
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer c1.Close()

	// 1. HTTP DeviceInfo over SSH dynamic tunnel
	info, err := c1.DeviceInfo(context.Background())
	if err != nil {
		t.Fatalf("DeviceInfo via SSH proxy failed: %v", err)
	}
	if info.Alias != "proxied-cam" {
		t.Fatalf("unexpected DeviceInfo: %+v", info)
	}

	// 2. Second client with same SSH host reuses the single running ssh tunnel
	c2, err := NewClient(config.Settings{
		Name:     "cam2",
		Host:     camHost,
		HTTPPort: httpPort,
		RTSPPort: rtspPort,
		User:     "admin",
		Password: "secret_pw",
		Proxy:    "ssh://ubuntu@home-nas:2222",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if _, err := c2.ActivationStatus(context.Background()); err != nil {
		t.Fatalf("c2 ActivationStatus via shared SSH tunnel failed: %v", err)
	}

	// 3. RTSPStreamURL opens a 127.0.0.1 bridge and tunnels RTSP traffic through SSH
	bridgeURL, err := c1.RTSPStreamURL(context.Background(), "stream1")
	if err != nil {
		t.Fatalf("RTSPStreamURL failed: %v", err)
	}
	parsedRTSP, err := url.Parse(bridgeURL)
	if err != nil || parsedRTSP.Hostname() != "127.0.0.1" {
		t.Fatalf("expected 127.0.0.1 loopback RTSP bridge URL, got %q", bridgeURL)
	}
	rtspConn, err := net.DialTimeout("tcp", parsedRTSP.Host, 2*time.Second)
	if err != nil {
		t.Fatalf("dial local RTSP bridge failed: %v", err)
	}
	_, _ = rtspConn.Write([]byte("OPTIONS rtsp://127.0.0.1/stream1 RTSP/1.0\r\nCSeq: 1\r\n\r\n"))
	reply := make([]byte, 256)
	n, err := rtspConn.Read(reply)
	_ = rtspConn.Close()
	if err != nil || !strings.Contains(string(reply[:n]), "RTSP/1.0 200 OK") {
		t.Fatalf("unexpected RTSP bridge reply: %q err=%v", string(reply[:n]), err)
	}

	// Verify only ONE ssh process was spawned and "-- ubuntu@home-nas" + "-p 2222" were passed
	logData, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(logData)), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected exactly 1 shared ssh process invocation, got %d:\n%s", len(lines), string(logData))
	}
	if !strings.Contains(lines[0], "-p 2222 -- ubuntu@home-nas") {
		t.Fatalf("expected '-p 2222 -- ubuntu@home-nas' in ssh args, got: %s", lines[0])
	}
	if hits.Load() < 4 {
		t.Fatalf("expected all HTTP and RTSP requests to reach mock camera, got %d hits", hits.Load())
	}

	// 4. SSH authentication failure surfaces clean diagnostic message
	t.Setenv("FAKE_SSH_FAIL", "1")
	badClient, _ := NewClient(config.Settings{
		Host:     camHost,
		HTTPPort: httpPort,
		Proxy:    "denied-host",
	})
	_, failErr := badClient.ActivationStatus(context.Background())
	if failErr == nil || !strings.Contains(failErr.Error(), "Permission denied") {
		t.Fatalf("expected SSH stderr 'Permission denied' surfaced, got: %v", failErr)
	}
}

func TestSOCKS5AndHTTPConnectProxies(t *testing.T) {
	camHost, httpPort, _, _ := startMockCameraAndRTSP(t)

	// 1. Authenticated SOCKS5 proxy
	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socksLn.Close()
	go func() {
		for {
			c, aErr := socksLn.Accept()
			if aErr != nil {
				return
			}
			go serveTestSOCKS5Conn(c, "suser", "spass_secret")
		}
	}()

	socksPort := socksLn.Addr().(*net.TCPAddr).Port
	cSocks, err := NewClient(config.Settings{
		Host:     camHost,
		HTTPPort: httpPort,
		User:     "admin",
		Password: "pw",
		Proxy:    fmt.Sprintf("socks5://suser:spass_secret@127.0.0.1:%d", socksPort),
	})
	if err != nil {
		t.Fatal(err)
	}
	if info, err := cSocks.DeviceInfo(context.Background()); err != nil || info.Model != "TL-IPC48AW-PLUS" {
		t.Fatalf("SOCKS5 DeviceInfo failed: info=%+v err=%v", info, err)
	}

	// 2. Authenticated HTTP CONNECT proxy
	httpProxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer httpProxyLn.Close()
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("huser:hpass_secret"))
	go func() {
		for {
			c, aErr := httpProxyLn.Accept()
			if aErr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				br := bufio.NewReader(conn)
				req, rErr := http.ReadRequest(br)
				if rErr != nil || req.Method != http.MethodConnect {
					return
				}
				if req.Header.Get("Proxy-Authorization") != wantAuth {
					_, _ = io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
					return
				}
				up, dErr := net.DialTimeout("tcp", req.Host, 3*time.Second)
				if dErr != nil {
					_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				defer up.Close()
				_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
				done := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(up, br); done <- struct{}{} }()
				go func() { _, _ = io.Copy(conn, up); done <- struct{}{} }()
				<-done
			}(c)
		}
	}()

	hpPort := httpProxyLn.Addr().(*net.TCPAddr).Port
	cHTTPProxy, err := NewClient(config.Settings{
		Host:     camHost,
		HTTPPort: httpPort,
		User:     "admin",
		Password: "pw",
		Proxy:    fmt.Sprintf("http://huser:hpass_secret@127.0.0.1:%d", hpPort),
	})
	if err != nil {
		t.Fatal(err)
	}
	if info, err := cHTTPProxy.DeviceInfo(context.Background()); err != nil || info.Alias != "proxied-cam" {
		t.Fatalf("HTTP CONNECT proxy DeviceInfo failed: info=%+v err=%v", info, err)
	}
}
