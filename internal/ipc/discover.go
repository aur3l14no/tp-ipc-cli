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
	"sort"
	"strings"
	"sync"
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

// DiscoverLAN broadcasts an ONVIF WS-Discovery UDP multicast probe to 239.255.255.250:3702
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

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("bind UDP discovery socket: %w", err)
	}
	defer conn.Close()

	_, _ = conn.WriteToUDP([]byte(probeXML), mcastAddr)
	_, _ = conn.WriteToUDP([]byte(probeXML), bcastAddr)

	deadline := time.Now().Add(timeout)
	byHost := make(map[string]DiscoveredCamera)
	buf := make([]byte, 16384)

	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			break
		}
		rem := time.Until(deadline)
		if rem > 250*time.Millisecond {
			rem = 250 * time.Millisecond
		}
		_ = conn.SetReadDeadline(time.Now().Add(rem))
		n, remote, rErr := conn.ReadFromUDP(buf)
		if n > 0 {
			cam, ok := parseProbeMatch(buf[:n], remote.IP.String())
			if ok && cam.Host != "" {
				byHost[cam.Host] = cam
			}
		}
		if rErr != nil {
			var netErr net.Error
			if errors.As(rErr, &netErr) && netErr.Timeout() {
				continue
			}
			break
		}
	}

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

// DiscoverCIDR scans a /24../32 IPv4 CIDR block concurrently via unauthenticated GET /pc/Content.htm,
// finding TP-Link TL-IPC cameras even across routed VLANs or VPNs where L2 multicast cannot cross.
func DiscoverCIDR(ctx context.Context, cidr string, timeout time.Duration) ([]DiscoveredCamera, error) {
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
						if cam.Model == "" {
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
