package ipc

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aur3l14no/tp-ipc-cli/internal/config"
)

type DiscoveredCamera struct {
	Host            string   `json:"host"`
	ONVIFEndpoint   string   `json:"onvif_endpoint,omitempty"`
	Types           string   `json:"types,omitempty"`
	Scopes          []string `json:"scopes,omitempty"`
	Model           string   `json:"model,omitempty"`
	Name            string   `json:"name,omitempty"`
	Hardware        string   `json:"hardware,omitempty"`
	IsTPLinkIPC     bool     `json:"is_tplink_ipc"`
	ActivationState string   `json:"activation_state,omitempty"`
}

type lanInterfaceTarget struct {
	localIP   net.IP
	broadcast net.IP
}

func activeLANIPv4Targets() []lanInterfaceTarget {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var targets []lanInterfaceTarget
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagPointToPoint != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() {
				continue
			}
			var bcast net.IP
			if mask := ipNet.Mask; len(mask) == net.IPv4len {
				bcast = net.IPv4(
					ip4[0]|^mask[0],
					ip4[1]|^mask[1],
					ip4[2]|^mask[2],
					ip4[3]|^mask[3],
				)
			}
			targets = append(targets, lanInterfaceTarget{
				localIP:   ip4,
				broadcast: bcast,
			})
		}
	}
	return targets
}

// DiscoverLAN broadcasts an ONVIF WS-Discovery UDP multicast probe to 239.255.255.250:3702
// across every active non-point-to-point IPv4 LAN interface (bypassing VPN/proxy utun routes)
// and checks whether responding hosts expose TP-Link's /pc/Content.htm challenge.
func DiscoverLAN(ctx context.Context, timeout time.Duration) ([]DiscoveredCamera, error) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if timeout > 15*time.Second {
		timeout = 15 * time.Second
	}

	msgID, err := randomUUID()
	if err != nil {
		return nil, err
	}
	probeXML := fmt.Sprintf(
		`<?xml version="1.0" encoding="UTF-8"?>`+
			`<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" `+
			`xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" `+
			`xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" `+
			`xmlns:dn="http://www.onvif.org/ver10/network/wsdl">`+
			`<e:Header>`+
			`<w:MessageID>uuid:%s</w:MessageID>`+
			`<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>`+
			`<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>`+
			`</e:Header>`+
			`<e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body>`+
			`</e:Envelope>`,
		msgID,
	)

	mcastAddr := &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 3702}
	bcastAddr := &net.UDPAddr{IP: net.IPv4bcast, Port: 3702}

	targets := activeLANIPv4Targets()
	if len(targets) == 0 {
		targets = []lanInterfaceTarget{{localIP: net.IPv4zero}}
	}

	type probeSocket struct {
		conn  *net.UDPConn
		dests []*net.UDPAddr
	}
	var (
		sockets         []probeSocket
		sentCount       int
		hostUnreachErrs int
	)
	defer func() {
		for _, s := range sockets {
			_ = s.conn.Close()
		}
	}()

	for _, t := range targets {
		conn, listenErr := net.ListenUDP("udp4", &net.UDPAddr{IP: t.localIP, Port: 0})
		if listenErr != nil {
			continue
		}

		if rawConn, scErr := conn.SyscallConn(); scErr == nil {
			_ = rawConn.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
				if ip4 := t.localIP.To4(); ip4 != nil && !ip4.Equal(net.IPv4zero) {
					var addr [4]byte
					copy(addr[:], ip4)
					_ = syscall.SetsockoptInet4Addr(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, addr)
				}
			})
		}

		dests := []*net.UDPAddr{mcastAddr}
		if t.broadcast != nil && !t.broadcast.Equal(net.IPv4bcast) {
			dests = append(dests, &net.UDPAddr{IP: t.broadcast, Port: 3702})
		} else {
			dests = append(dests, bcastAddr)
		}
		sockets = append(sockets, probeSocket{conn: conn, dests: dests})
		for _, dst := range dests {
			if _, wErr := conn.WriteToUDP([]byte(probeXML), dst); wErr != nil {
				if errors.Is(wErr, syscall.EHOSTUNREACH) {
					hostUnreachErrs++
				}
			} else {
				sentCount++
			}
		}
	}

	if len(sockets) == 0 {
		return nil, errors.New("failed to bind any UDPv4 socket for WS-Discovery")
	}
	if sentCount == 0 && hostUnreachErrs > 0 && runtime.GOOS == "darwin" {
		return nil, errors.New("UDP LAN discovery blocked with EHOSTUNREACH (no route to host): enable System Settings -> Privacy & Security -> Local Network for your terminal or host app")
	}

	deadline := time.Now().Add(timeout)
	retryDone := make(chan struct{})
	defer close(retryDone)
	if timeout >= 700*time.Millisecond {
		go func() {
			timer := time.NewTimer(350 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-timer.C:
				for _, s := range sockets {
					for _, dst := range s.dests {
						_, _ = s.conn.WriteToUDP([]byte(probeXML), dst)
					}
				}
			case <-ctx.Done():
			case <-retryDone:
			}
		}()
	}

	var (
		byHostMu sync.Mutex
		byHost   = make(map[string]DiscoveredCamera)
		readWG   sync.WaitGroup
	)
	for _, s := range sockets {
		readWG.Add(1)
		go func(c *net.UDPConn) {
			defer readWG.Done()
			buf := make([]byte, 16384)
			for time.Now().Before(deadline) {
				if ctx.Err() != nil {
					return
				}
				rem := time.Until(deadline)
				if rem > 250*time.Millisecond {
					rem = 250 * time.Millisecond
				}
				_ = c.SetReadDeadline(time.Now().Add(rem))
				n, remote, rErr := c.ReadFromUDP(buf)
				if n > 0 {
					if cam, ok := parseProbeMatch(buf[:n], remote.IP.String()); ok && cam.Host != "" {
						byHostMu.Lock()
						byHost[cam.Host] = cam
						byHostMu.Unlock()
					}
				}
				if rErr != nil {
					var netErr net.Error
					if errors.As(rErr, &netErr) && netErr.Timeout() {
						continue
					}
					return
				}
			}
		}(s.conn)
	}
	readWG.Wait()

	results := make([]DiscoveredCamera, 0, len(byHost))
	for _, c := range byHost {
		results = append(results, c)
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Host < results[j].Host
	})

	// Probe /pc/Content.htm concurrently to identify TP-Link TL-IPC firmware & activation status
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			probeCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
			defer cancel()
			cl, err := NewClient(config.Settings{
				Scheme:   "http",
				Host:     results[idx].Host,
				HTTPPort: 80,
			})
			if err != nil {
				return
			}
			if st, err := cl.ActivationStatus(probeCtx); err == nil {
				results[idx].IsTPLinkIPC = true
				results[idx].ActivationState = st.State
			}
		}(i)
	}
	wg.Wait()

	return results, nil
}

// DiscoverCIDR scans a /22../32 IPv4 CIDR block concurrently via unauthenticated GET /pc/Content.htm,
// finding TP-Link TL-IPC cameras even across routed VLANs or VPNs where L2 multicast cannot cross.
func DiscoverCIDR(ctx context.Context, cidr string, timeout time.Duration) ([]DiscoveredCamera, error) {
	return DiscoverCIDRWithProxy(ctx, cidr, "", timeout)
}

// DiscoverCIDRWithProxy scans a /22../32 IPv4 CIDR block optionally through an SSH/SOCKS5/HTTP proxy.
func DiscoverCIDRWithProxy(ctx context.Context, cidr string, rawProxy string, timeout time.Duration) ([]DiscoveredCamera, error) {
	prefixIP, ipNet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q (example: 192.168.1.0/24): %w", cidr, err)
	}
	v4 := prefixIP.To4()
	if v4 == nil {
		return nil, errors.New("only IPv4 CIDR blocks are supported for subnet scan")
	}
	ones, bits := ipNet.Mask.Size()
	if bits != 32 || ones < 22 {
		return nil, errors.New("CIDR prefix must be /22 or narrower (max 1024 hosts)")
	}
	if timeout <= 0 {
		timeout = 800 * time.Millisecond
	}

	var pSpec config.ProxySpec
	canonicalProxy := ""
	if strings.TrimSpace(rawProxy) != "" {
		pSpec, err = config.ParseProxyInput(rawProxy)
		if err != nil {
			return nil, err
		}
		if !pSpec.DirectOverride {
			canonicalProxy = pSpec.Canonical()
		}
	}
	if pSpec.Kind == "ssh" {
		warmCtx, cancelWarm := context.WithTimeout(ctx, 15*time.Second)
		_, warmErr := globalSSHPool.getTunnel(warmCtx, pSpec)
		cancelWarm()
		if warmErr != nil {
			return nil, warmErr
		}
	}

	var hosts []string
	base := uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
	mask := uint32(0xffffffff) << (32 - ones)
	start := base & mask
	count := uint32(1) << (32 - ones)
	for i := uint32(0); i < count; i++ {
		if ones <= 30 && (i == 0 || i == count-1) {
			continue // skip network and broadcast addresses
		}
		v := start + i
		ip := net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).String()
		hosts = append(hosts, ip)
	}

	jobs := make(chan string, len(hosts))
	for _, h := range hosts {
		jobs <- h
	}
	close(jobs)

	var (
		mu    sync.Mutex
		found []DiscoveredCamera
		wg    sync.WaitGroup
	)
	workers := 64
	if pSpec.Kind == "ssh" {
		// Default OpenSSH sshd MaxSessions is 10 per multiplexed connection; stay safely below 10.
		workers = 8
	}
	if len(hosts) < workers {
		workers = len(hosts)
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				if ctx.Err() != nil {
					return
				}
				pCtx, cancel := context.WithTimeout(ctx, timeout)
				cl, err := NewClient(config.Settings{
					Scheme:   "http",
					Host:     host,
					HTTPPort: 80,
					Proxy:    canonicalProxy,
				})
				if err == nil {
					if st, aErr := cl.ActivationStatus(pCtx); aErr == nil {
						mu.Lock()
						found = append(found, DiscoveredCamera{
							Host:            host,
							ONVIFEndpoint:   fmt.Sprintf("http://%s:2020/onvif/service", host),
							IsTPLinkIPC:     true,
							ActivationState: st.State,
						})
						mu.Unlock()
					}
				}
				cancel()
			}
		}()
	}
	wg.Wait()

	sort.Slice(found, func(i, j int) bool {
		return found[i].Host < found[j].Host
	})
	return found, nil
}

func parseProbeMatch(data []byte, fallbackIP string) (DiscoveredCamera, bool) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	var cam DiscoveredCamera
	cam.Host = fallbackIP
	inMatch := false
	curField := ""

	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return cam, false
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "ProbeMatch":
				inMatch = true
			case "Types", "Scopes", "XAddrs":
				if inMatch {
					curField = t.Name.Local
				}
			}
		case xml.CharData:
			if !inMatch || curField == "" {
				continue
			}
			val := strings.TrimSpace(string(t))
			if val == "" {
				continue
			}
			switch curField {
			case "Types":
				cam.Types = val
			case "Scopes":
				cam.Scopes = strings.Fields(val)
				for _, sc := range cam.Scopes {
					decoded, err := url.PathUnescape(sc)
					if err != nil {
						decoded = sc
					}
					switch {
					case strings.HasPrefix(decoded, "onvif://www.onvif.org/hardware/"):
						cam.Hardware = strings.TrimPrefix(decoded, "onvif://www.onvif.org/hardware/")
						if cam.Model == "" && !strings.EqualFold(cam.Hardware, "MODEL") {
							cam.Model = cam.Hardware
						}
					case strings.HasPrefix(decoded, "onvif://www.onvif.org/name/"):
						cam.Name = strings.TrimPrefix(decoded, "onvif://www.onvif.org/name/")
						if cam.Model == "" {
							cam.Model = cam.Name
						}
					}
				}
			case "XAddrs":
				fields := strings.Fields(val)
				if len(fields) > 0 {
					cam.ONVIFEndpoint = fields[0]
					if u, err := url.Parse(fields[0]); err == nil && u.Hostname() != "" {
						cam.Host = u.Hostname()
					}
				}
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "Types", "Scopes", "XAddrs":
				curField = ""
			case "ProbeMatch":
				return cam, true
			}
		}
	}
	return cam, inMatch
}
