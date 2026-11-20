package ipc

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aur3l14no/tp-ipc-cli/internal/config"
)

type syncByteBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncByteBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncByteBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type sshTunnelKey struct {
	sshBin string
	target string
	port   int
}

type sshTunnel struct {
	key       sshTunnelKey
	label     string
	socksAddr string
	readyCh   chan struct{}
	doneCh    chan struct{}
	stopCh    chan struct{}

	mu      sync.Mutex
	cmd     *exec.Cmd
	stopped bool
	initErr error
	waitErr error
}

func (t *sshTunnel) isDead() bool {
	select {
	case <-t.doneCh:
		return true
	default:
		return false
	}
}

func (t *sshTunnel) stop() {
	t.mu.Lock()
	if !t.stopped {
		t.stopped = true
		close(t.stopCh)
	}
	cmd := t.cmd
	t.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-t.doneCh:
		return
	case <-time.After(150 * time.Millisecond):
		_ = cmd.Process.Kill()
		select {
		case <-t.doneCh:
		case <-time.After(200 * time.Millisecond):
		}
	}
}

type sshTunnelPool struct {
	mu          sync.Mutex
	sshBinFixed string
	tunnels     map[sshTunnelKey]*sshTunnel
}

var globalSSHPool = &sshTunnelPool{
	tunnels: make(map[sshTunnelKey]*sshTunnel),
}

// CloseSharedProxies terminates any background SSH dynamic-forwarding processes started in this process.
func CloseSharedProxies() {
	globalSSHPool.closeAll()
}

func (p *sshTunnelPool) closeAll() {
	p.mu.Lock()
	list := make([]*sshTunnel, 0, len(p.tunnels))
	for k, t := range p.tunnels {
		list = append(list, t)
		delete(p.tunnels, k)
	}
	p.mu.Unlock()

	for _, t := range list {
		t.stop()
	}
}

func (p *sshTunnelPool) resolveSSHBin() (string, error) {
	p.mu.Lock()
	override := p.sshBinFixed
	p.mu.Unlock()
	if override != "" {
		return override, nil
	}
	bin, err := exec.LookPath("ssh")
	if err != nil {
		return "", errors.New("ssh client not found in PATH (required for SSH proxy)")
	}
	return bin, nil
}

func (p *sshTunnelPool) evictIfSame(key sshTunnelKey, t *sshTunnel) {
	p.mu.Lock()
	if cur, ok := p.tunnels[key]; ok && cur == t {
		delete(p.tunnels, key)
	}
	p.mu.Unlock()
}

func (p *sshTunnelPool) getTunnel(ctx context.Context, spec config.ProxySpec) (*sshTunnel, error) {
	sshBin, err := p.resolveSSHBin()
	if err != nil {
		return nil, err
	}
	key := sshTunnelKey{
		sshBin: sshBin,
		target: spec.SSHTarget,
		port:   spec.Port,
	}

	p.mu.Lock()
	tun, ok := p.tunnels[key]
	if !ok || tun.isDead() {
		tun = &sshTunnel{
			key:     key,
			label:   spec.Redacted(),
			readyCh: make(chan struct{}),
			doneCh:  make(chan struct{}),
			stopCh:  make(chan struct{}),
		}
		p.tunnels[key] = tun
		go tun.start(p)
	}
	p.mu.Unlock()

	select {
	case <-tun.readyCh:
		tun.mu.Lock()
		initErr := tun.initErr
		tun.mu.Unlock()
		if initErr != nil {
			return nil, initErr
		}
		return tun, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func reserveLoopbackPort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port, nil
}

func (t *sshTunnel) start(pool *sshTunnelPool) {
	var lastErr error
attemptLoop:
	for attempt := 0; attempt < 3; attempt++ {
		select {
		case <-t.stopCh:
			lastErr = errors.New("ssh proxy stopped")
			break attemptLoop
		default:
		}

		port, err := reserveLoopbackPort()
		if err != nil {
			lastErr = fmt.Errorf("allocate local SOCKS port: %w", err)
			break
		}
		socksAddr := fmt.Sprintf("127.0.0.1:%d", port)
		args := []string{
			"-N", "-T",
			"-D", socksAddr,
			"-o", "ExitOnForwardFailure=yes",
			"-o", "BatchMode=yes",
			"-o", "ControlPersist=no",
			"-o", "ConnectTimeout=10",
			"-o", "ServerAliveInterval=15",
			"-o", "ServerAliveCountMax=3",
			"-o", "LogLevel=ERROR",
		}
		if t.key.port > 0 {
			args = append(args, "-p", strconv.Itoa(t.key.port))
		}
		args = append(args, "--", t.key.target)

		var stderr syncByteBuffer
		cmd := exec.Command(t.key.sshBin, args...)
		cmd.Stderr = &stderr
		if err := cmd.Start(); err != nil {
			lastErr = fmt.Errorf("start ssh proxy (%s): %w", t.label, err)
			break
		}

		t.mu.Lock()
		if t.stopped {
			t.mu.Unlock()
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			lastErr = errors.New("ssh proxy stopped")
			break attemptLoop
		}
		t.cmd = cmd
		t.mu.Unlock()

		procDone := make(chan error, 1)
		go func() {
			procDone <- cmd.Wait()
		}()

		ready, retryBind, waitErr := waitForLocalSOCKS(socksAddr, procDone, t.stopCh, &stderr, t.label)
		if ready {
			t.socksAddr = socksAddr
			close(t.readyCh)
			err := <-procDone
			t.mu.Lock()
			t.waitErr = err
			t.mu.Unlock()
			pool.evictIfSame(t.key, t)
			close(t.doneCh)
			return
		}

		_ = cmd.Process.Kill()
		select {
		case <-procDone:
		case <-time.After(200 * time.Millisecond):
		}
		t.mu.Lock()
		if t.cmd == cmd {
			t.cmd = nil
		}
		t.mu.Unlock()
		lastErr = waitErr
		if !retryBind {
			break
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("ssh proxy (%s) failed to start", t.label)
	}
	t.mu.Lock()
	t.initErr = lastErr
	t.mu.Unlock()
	pool.evictIfSame(t.key, t)
	close(t.doneCh)
	close(t.readyCh)
}

func waitForLocalSOCKS(socksAddr string, procDone <-chan error, stopCh <-chan struct{}, stderr *syncByteBuffer, label string) (ready bool, retryBind bool, err error) {
	deadline := time.Now().Add(14 * time.Second)
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return false, false, errors.New("ssh proxy stopped")
		default:
		}

		conn, dialErr := net.DialTimeout("tcp", socksAddr, 150*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			return true, false, nil
		}

		select {
		case <-stopCh:
			return false, false, errors.New("ssh proxy stopped")
		case wErr := <-procDone:
			msg := strings.TrimSpace(stderr.String())
			lower := strings.ToLower(msg)
			if strings.Contains(lower, "address already in use") || strings.Contains(lower, "cannot listen to port") {
				return false, true, fmt.Errorf("ssh proxy (%s): %s", label, msg)
			}
			if msg != "" {
				return false, false, fmt.Errorf("ssh proxy (%s) failed: %s", label, msg)
			}
			if wErr != nil {
				return false, false, fmt.Errorf("ssh proxy (%s) failed: %w", label, wErr)
			}
			return false, false, fmt.Errorf("ssh proxy (%s) exited unexpectedly", label)
		default:
		}

		if time.Now().After(deadline) {
			msg := strings.TrimSpace(stderr.String())
			if msg != "" {
				return false, false, fmt.Errorf("ssh proxy (%s) timed out: %s", label, msg)
			}
			return false, false, fmt.Errorf("ssh proxy (%s) timed out waiting for tunnel", label)
		}

		select {
		case <-stopCh:
			return false, false, errors.New("ssh proxy stopped")
		case <-ticker.C:
		}
	}
}

func (c *Client) dialWithTimeout(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	if c.proxySpec.Kind == "" {
		return (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 15 * time.Second,
		}).DialContext(ctx, network, address)
	}

	targetHost, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid target address %q: %w", address, err)
	}
	targetPort, err := strconv.Atoi(portStr)
	if err != nil || targetPort < 1 || targetPort > 65535 {
		return nil, fmt.Errorf("invalid target port %q", portStr)
	}

	switch c.proxySpec.Kind {
	case "ssh":
		tun, err := globalSSHPool.getTunnel(ctx, c.proxySpec)
		if err != nil {
			return nil, err
		}
		conn, err := dialSOCKS5(ctx, tun.socksAddr, "", "", targetHost, targetPort, timeout)
		if err != nil && tun.isDead() && ctx.Err() == nil {
			// Tunnel died (e.g. after sleep/network change); reconnect once transparently.
			globalSSHPool.evictIfSame(tun.key, tun)
			tun2, err2 := globalSSHPool.getTunnel(ctx, c.proxySpec)
			if err2 != nil {
				return nil, err2
			}
			return dialSOCKS5(ctx, tun2.socksAddr, "", "", targetHost, targetPort, timeout)
		}
		return conn, err

	case "socks5":
		proxyAddr := net.JoinHostPort(c.proxySpec.Host, strconv.Itoa(c.proxySpec.Port))
		return dialSOCKS5(ctx, proxyAddr, c.proxySpec.User, c.proxySpec.Password, targetHost, targetPort, timeout)

	case "http", "https":
		return dialHTTPConnect(ctx, c.proxySpec, address, timeout)

	default:
		return nil, fmt.Errorf("unsupported proxy type %q", c.proxySpec.Kind)
	}
}

func dialSOCKS5(ctx context.Context, proxyAddr, user, password, targetHost string, targetPort int, timeout time.Duration) (net.Conn, error) {
	dialer := net.Dialer{Timeout: timeout, KeepAlive: 15 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("connect SOCKS5 proxy %s: %w", proxyAddr, err)
	}

	ok := false
	stopCancel := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	defer func() {
		stopCancel()
		if !ok {
			_ = conn.Close()
		}
	}()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// 1. Method negotiation
	if user != "" || password != "" {
		if _, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
			return nil, err
		}
	} else {
		if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			return nil, err
		}
	}

	var methodReply [2]byte
	if _, err := io.ReadFull(conn, methodReply[:]); err != nil {
		return nil, fmt.Errorf("SOCKS5 greeting failed: %w", err)
	}
	if methodReply[0] != 0x05 {
		return nil, fmt.Errorf("unexpected SOCKS version %d", methodReply[0])
	}
	switch methodReply[1] {
	case 0x00:
		// No auth required
	case 0x02:
		if len(user) > 255 || len(password) > 255 {
			return nil, errors.New("SOCKS5 credentials exceed 255 bytes")
		}
		authReq := make([]byte, 0, 3+len(user)+len(password))
		authReq = append(authReq, 0x01, byte(len(user)))
		authReq = append(authReq, user...)
		authReq = append(authReq, byte(len(password)))
		authReq = append(authReq, password...)
		if _, err := conn.Write(authReq); err != nil {
			return nil, err
		}
		var authReply [2]byte
		if _, err := io.ReadFull(conn, authReply[:]); err != nil {
			return nil, fmt.Errorf("SOCKS5 auth failed: %w", err)
		}
		if authReply[1] != 0x00 {
			return nil, errors.New("SOCKS5 authentication rejected")
		}
	case 0xff:
		return nil, errors.New("SOCKS5 proxy rejected authentication methods")
	default:
		return nil, fmt.Errorf("unsupported SOCKS5 auth method 0x%02x", methodReply[1])
	}

	// 2. CONNECT request
	req := make([]byte, 0, 7+len(targetHost))
	req = append(req, 0x05, 0x01, 0x00)
	if ip := net.ParseIP(targetHost); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01)
			req = append(req, v4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(targetHost) > 255 {
			return nil, fmt.Errorf("target hostname %q too long for SOCKS5", targetHost)
		}
		req = append(req, 0x03, byte(len(targetHost)))
		req = append(req, targetHost...)
	}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(targetPort))
	req = append(req, portBytes[:]...)

	if _, err := conn.Write(req); err != nil {
		return nil, err
	}

	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, fmt.Errorf("SOCKS5 connect read failed: %w", err)
	}
	if hdr[1] != 0x00 {
		return nil, fmt.Errorf("proxy connect to %s:%d failed (%s)", targetHost, targetPort, socks5ReplyText(hdr[1]))
	}

	var drainLen int
	switch hdr[3] {
	case 0x01:
		drainLen = 4 + 2
	case 0x04:
		drainLen = 16 + 2
	case 0x03:
		var dlen [1]byte
		if _, err := io.ReadFull(conn, dlen[:]); err != nil {
			return nil, err
		}
		drainLen = int(dlen[0]) + 2
	default:
		return nil, fmt.Errorf("unknown SOCKS5 address type 0x%02x", hdr[3])
	}
	if _, err := io.CopyN(io.Discard, conn, int64(drainLen)); err != nil {
		return nil, err
	}

	_ = conn.SetDeadline(time.Time{})
	ok = true
	return conn, nil
}

func socks5ReplyText(code byte) string {
	switch code {
	case 0x01:
		return "general SOCKS server failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable from proxy host"
	case 0x04:
		return "camera host unreachable from proxy host"
	case 0x05:
		return "connection refused by camera"
	case 0x06:
		return "connection timed out on proxy host"
	default:
		return fmt.Sprintf("SOCKS5 code 0x%02x", code)
	}
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (bc *bufferedConn) Read(p []byte) (int, error) {
	return bc.r.Read(p)
}

func dialHTTPConnect(ctx context.Context, spec config.ProxySpec, targetAddr string, timeout time.Duration) (net.Conn, error) {
	proxyAddr := net.JoinHostPort(spec.Host, strconv.Itoa(spec.Port))
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 15 * time.Second}

	var (
		conn net.Conn
		err  error
	)
	if spec.Kind == "https" {
		tlsDialer := &tls.Dialer{
			NetDialer: dialer,
			Config:    &tls.Config{ServerName: spec.Host},
		}
		conn, err = tlsDialer.DialContext(ctx, "tcp", proxyAddr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", proxyAddr)
	}
	if err != nil {
		return nil, fmt.Errorf("connect HTTP proxy %s: %w", proxyAddr, err)
	}

	ok := false
	stopCancel := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	defer func() {
		stopCancel()
		if !ok {
			_ = conn.Close()
		}
	}()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	var reqBuf strings.Builder
	fmt.Fprintf(&reqBuf, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr)
	if spec.User != "" || spec.Password != "" {
		cred := base64.StdEncoding.EncodeToString([]byte(spec.User + ":" + spec.Password))
		fmt.Fprintf(&reqBuf, "Proxy-Authorization: Basic %s\r\n", cred)
	}
	reqBuf.WriteString("\r\n")

	if _, err := io.WriteString(conn, reqBuf.String()); err != nil {
		return nil, err
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, fmt.Errorf("HTTP proxy CONNECT %s: %w", targetAddr, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP proxy CONNECT %s rejected (HTTP %d %s)", targetAddr, resp.StatusCode, resp.Status)
	}

	_ = conn.SetDeadline(time.Time{})
	ok = true
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: br}, nil
	}
	return conn, nil
}

// RTSPStreamURL returns the RTSP URL that local media subprocesses (ffmpeg, ffplay, mpv) should open.
// When no proxy is configured, it returns the direct camera RTSP URL.
// When a proxy (SSH, SOCKS5, or HTTP CONNECT) is configured, it warms the proxy and returns a
// local 127.0.0.1 loopback bridge URL whose TCP connections are tunneled through the proxy.
func (c *Client) RTSPStreamURL(ctx context.Context, stream string) (string, error) {
	if c.proxySpec.Kind == "" {
		return c.cfg.RTSPURL(stream, false), nil
	}
	if c.proxySpec.Kind == "ssh" {
		if _, err := globalSSHPool.getTunnel(ctx, c.proxySpec); err != nil {
			return "", err
		}
	}

	port, err := c.ensureRTSPBridge()
	if err != nil {
		return "", err
	}
	u := url.PathEscape(c.cfg.User)
	pw := url.PathEscape(c.cfg.Password)
	return fmt.Sprintf("rtsp://%s:%s@127.0.0.1:%d/%s", u, pw, port, strings.TrimPrefix(stream, "/")), nil
}

func (c *Client) ensureRTSPBridge() (int, error) {
	c.bridgeMu.Lock()
	defer c.bridgeMu.Unlock()
	if c.rtspBridgeLn != nil {
		return c.rtspBridgePort, nil
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("bind local RTSP proxy bridge: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	c.rtspBridgeLn = ln
	c.rtspBridgePort = port

	remoteAddr := net.JoinHostPort(c.cfg.Host, strconv.Itoa(c.cfg.RTSPPort))
	go func() {
		for {
			localConn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go c.relayRTSPConn(localConn, remoteAddr)
		}
	}()
	return port, nil
}

func (c *Client) relayRTSPConn(localConn net.Conn, remoteAddr string) {
	dialCtx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	remoteConn, err := c.dialWithTimeout(dialCtx, "tcp", remoteAddr, 10*time.Second)
	cancel()
	if err != nil {
		_ = localConn.Close()
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	pump := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if tc, ok := dst.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	go pump(remoteConn, localConn)
	go pump(localConn, remoteConn)
	wg.Wait()
	_ = localConn.Close()
	_ = remoteConn.Close()
}

// Close releases any local RTSP proxy bridge listener held by this Client.
func (c *Client) Close() error {
	c.bridgeMu.Lock()
	ln := c.rtspBridgeLn
	c.rtspBridgeLn = nil
	c.rtspBridgePort = 0
	c.bridgeMu.Unlock()
	if ln != nil {
		return ln.Close()
	}
	return nil
}
