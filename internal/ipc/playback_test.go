package ipc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aur3l14no/tp-ipc-cli/internal/config"
)

func TestParseTimeWindowAndPlanSegments(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	s, e, err := ParseTimeWindow("2026-11-12", "12:00", "12:10", loc)
	if err != nil {
		t.Fatalf("ParseTimeWindow failed: %v", err)
	}
	if e-s != 600 {
		t.Fatalf("expected 600s window, got %d", e-s)
	}

	segs := []RecordingSegment{
		{StartUnix: s - 30, EndUnix: s + 120, VideoType: 2},
		{StartUnix: s + 300, EndUnix: s + 420, VideoType: 2},
	}
	spans, mediaDur, gapDur := planExportSegments(segs, s, e)
	if len(spans) != 2 || mediaDur != 240 || gapDur != 360 {
		t.Fatalf("unexpected plan: spans=%+v media=%d gap=%d", spans, mediaDur, gapDur)
	}

	sdp := buildPlaybackSDP(40000, 40002, 96, 97, avStreamConfig{
		VideoCodec:        "H265",
		AudioCodec:        "AAC",
		AudioSamplingRate: 16,
		AudioChannels:     1,
	}, map[byte][]byte{
		32: []byte{0x40, 0x01, 0x0c},
		33: []byte{0x42, 0x01, 0x01},
		34: []byte{0x44, 0x01, 0xc0},
	})
	if !strings.Contains(sdp, "sprop-vps=") || !strings.Contains(sdp, "MPEG4-GENERIC/16000/1") {
		t.Fatalf("unexpected SDP:\n%s", sdp)
	}

	g711SDP := buildPlaybackSDP(40000, 40002, 96, 8, avStreamConfig{
		VideoCodec:        "H265",
		AudioCodec:        "G711A",
		AudioSamplingRate: 8,
		AudioChannels:     1,
	}, nil)
	if !strings.Contains(g711SDP, "a=rtpmap:8 PCMA/8000/1") {
		t.Fatalf("expected G711A to map to PCMA/8000/1, got:\n%s", g711SDP)
	}

	for i := 0; i < 10; i++ {
		p1, p2, err := reserveTwoUDPPorts()
		if err != nil {
			t.Fatalf("reserveTwoUDPPorts failed: %v", err)
		}
		if p1%2 != 0 || p2%2 != 0 || p1 == p2 || p1+1 == p2 || p2+1 == p1 {
			t.Fatalf("invalid RTP/RTCP UDP port pair: p1=%d p2=%d", p1, p2)
		}
	}
}

func TestLoginTransportErrorDoesNotDeadlock(t *testing.T) {
	// 1. Closed local TCP port during /pc/Content.htm challenge
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	c, err := NewClient(config.Settings{
		Scheme:   "http",
		Host:     "127.0.0.1",
		HTTPPort: closedPort,
		User:     "admin",
		Password: "super_secret_password_123",
	})
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, callErr := c.DoDS(context.Background(), map[string]any{"method": "get"})
		done <- callErr
	}()

	select {
	case callErr := <-done:
		if callErr == nil {
			t.Fatal("expected error when camera port is closed")
		}
		if strings.Contains(callErr.Error(), "super_secret_password_123") {
			t.Fatalf("error leaked password: %v", callErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("DoDS deadlocked on login transport error")
	}

	// 2. Challenge succeeds, POST / drops connection abruptly
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	spki, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	keyB64 := base64.StdEncoding.EncodeToString(spki)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pc/Content.htm" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error_code": -40401,
				"data": map[string]any{
					"code":  -40407,
					"key":   keyB64,
					"nonce": "n999",
				},
			})
			return
		}
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, _ := hj.Hijack()
			_ = conn.Close()
		}
	}))
	defer srv.Close()

	_, host, port, _ := config.ParseHostInput(srv.URL)
	c2, _ := NewClient(config.Settings{
		Scheme:   "http",
		Host:     host,
		HTTPPort: port,
		User:     "admin",
		Password: "super_secret_password_123",
	})
	done2 := make(chan error, 1)
	go func() {
		_, callErr := c2.DoDS(context.Background(), map[string]any{"method": "get"})
		done2 <- callErr
	}()
	select {
	case callErr := <-done2:
		if callErr == nil {
			t.Fatal("expected error on dropped login POST")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("DoDS deadlocked on dropped login POST")
	}
}

func TestMultitransPlaybackMalformedResponsesAndCancellation(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
	}{
		{
			name:    "negative_content_length",
			payload: []byte("RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: -1\r\n\r\n"),
		},
		{
			name:    "non_numeric_content_length",
			payload: []byte("RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: bogus\r\n\r\n"),
		},
		{
			name:    "oversized_content_length",
			payload: []byte("RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 99999999\r\n\r\n"),
		},
		{
			name:    "oversized_unterminated_header",
			payload: append([]byte("RTSP/1.0 200 OK\r\nX-Junk: "), bytes.Repeat([]byte("A"), 70*1024)...),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			go func() {
				conn, aErr := ln.Accept()
				if aErr != nil {
					return
				}
				defer conn.Close()
				buf := make([]byte, 1024)
				_, _ = conn.Read(buf)
				_, _ = conn.Write(tc.payload)
			}()

			c, _ := NewClient(config.Settings{
				Scheme:   "http",
				Host:     "127.0.0.1",
				RTSPPort: ln.Addr().(*net.TCPAddr).Port,
				User:     "admin",
				Password: "pw",
			})
			_, _, sErr := c.streamSinglePlaybackChunk(
				context.Background(),
				1,
				1000,
				1010,
				func(avStreamConfig) {},
				func(byte, []byte) (bool, error) { return false, nil },
			)
			if sErr == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}

	// Verify mid-stream context cancellation unblocks promptly instead of waiting 3s read deadline
	t.Run("mid_stream_context_cancel", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		holdOpen := make(chan struct{})
		defer close(holdOpen)
		go func() {
			conn, aErr := ln.Accept()
			if aErr != nil {
				return
			}
			defer conn.Close()
			buf := make([]byte, 1024)
			_, _ = conn.Read(buf)
			body := `{"params":{"error_code":0,"av_config":[{"video_codec":"H265"}]}}`
			hdr := fmt.Sprintf("RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
			_, _ = conn.Write([]byte(hdr))
			// Send one valid RTP video packet, then stall socket open
			rtp := make([]byte, 16)
			rtp[0] = 0x80
			rtp[1] = 96
			binary.BigEndian.PutUint16(rtp[2:4], 1)
			binary.BigEndian.PutUint32(rtp[4:8], 90000)
			frame := make([]byte, 4+len(rtp))
			frame[0] = 0x24
			frame[1] = 0
			binary.BigEndian.PutUint16(frame[2:4], uint16(len(rtp)))
			copy(frame[4:], rtp)
			_, _ = conn.Write(frame)
			<-holdOpen
		}()

		c, _ := NewClient(config.Settings{
			Scheme:   "http",
			Host:     "127.0.0.1",
			RTSPPort: ln.Addr().(*net.TCPAddr).Port,
			User:     "admin",
			Password: "pw",
		})
		ctx, cancel := context.WithCancel(context.Background())
		pktSeen := make(chan struct{}, 1)
		start := time.Now()
		go func() {
			<-pktSeen
			time.Sleep(20 * time.Millisecond)
			cancel()
		}()
		_, _, sErr := c.streamSinglePlaybackChunk(
			ctx,
			1,
			1000,
			1010,
			func(avStreamConfig) {},
			func(byte, []byte) (bool, error) {
				select {
				case pktSeen <- struct{}{}:
				default:
				}
				return false, nil
			},
		)
		if !errors.Is(sErr, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", sErr)
		}
		if elapsed := time.Since(start); elapsed > 600*time.Millisecond {
			t.Fatalf("cancellation took too long (%v)", elapsed)
		}
	})
}

func TestRecordClipPreservesExistingFileAndExportPathContainment(t *testing.T) {
	tmp := t.TempDir()
	binDir := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fakeFFmpeg := filepath.Join(binDir, "ffmpeg")
	// Fake ffmpeg immediately exits 1 before touching output
	if err := os.WriteFile(fakeFFmpeg, []byte("#!/bin/sh\necho 'simulated rtsp failure' >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	existing := filepath.Join(tmp, "important.mp4")
	sentinel := []byte("ORIGINAL_USER_VIDEO_BYTES")
	if err := os.WriteFile(existing, sentinel, 0o644); err != nil {
		t.Fatal(err)
	}

	c, _ := NewClient(config.Settings{
		Scheme:   "http",
		Host:     "127.0.0.1",
		RTSPPort: 554,
		User:     "admin",
		Password: "pw",
	})
	if _, err := c.RecordClip(context.Background(), 3, false, existing, ""); err == nil {
		t.Fatal("expected RecordClip to fail with failing ffmpeg")
	}

	got, err := os.ReadFile(existing)
	if err != nil {
		t.Fatalf("existing file was deleted on failure: %v", err)
	}
	if !bytes.Equal(got, sentinel) {
		t.Fatalf("existing file contents changed: %q", string(got))
	}

	// Verify resolveExportOutputPath never escapes mediaDir even if Settings.Name has ../
	mediaDir := filepath.Join(tmp, "media")
	if err := os.MkdirAll(mediaDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cTraversal, _ := NewClient(config.Settings{
		Name:     "/../../escaped",
		Scheme:   "http",
		Host:     "127.0.0.1",
		MediaDir: mediaDir,
		User:     "admin",
		Password: "pw",
	})
	resolved, err := cTraversal.resolveExportOutputPath("", "", 1700000000, 1700000060)
	if err != nil {
		t.Fatalf("resolveExportOutputPath failed: %v", err)
	}
	if filepath.Dir(resolved) != mediaDir {
		t.Fatalf("export path %q escaped mediaDir %q", resolved, mediaDir)
	}
}

func TestPollEventsLongPollUsesDedicatedClient(t *testing.T) {
	var subPort int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := os.ReadFile("/dev/null")
		_ = body
		w.Header().Set("Content-Type", "application/soap+xml")
		if r.URL.Path == "/onvif/service" {
			fmt.Fprintf(w, `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><tev:CreatePullPointSubscriptionResponse xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:wsa="http://www.w3.org/2005/08/addressing"><tev:SubscriptionReference><wsa:Address>http://192.168.1.10:%d/event-1</wsa:Address></tev:SubscriptionReference></tev:CreatePullPointSubscriptionResponse></s:Body></s:Envelope>`, subPort)
			return
		}
		if strings.Contains(r.Header.Get("SOAPAction"), "PullMessagesRequest") {
			// Sleep longer than c.httpClient.Timeout (set to 80ms below) to prove PullMessages uses longPollClient
			time.Sleep(250 * time.Millisecond)
			_, _ = w.Write([]byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><tev:PullMessagesResponse xmlns:tev="http://www.onvif.org/ver10/events/wsdl"/></s:Body></s:Envelope>`))
			return
		}
		_, _ = w.Write([]byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><wsnt:UnsubscribeResponse xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2"/></s:Body></s:Envelope>`))
	}))
	defer srv.Close()

	_, host, portStr, _ := config.ParseHostInput(srv.URL)
	subPort = portStr
	_ = strconv.Itoa(subPort)

	c, err := NewClient(config.Settings{
		Scheme:    "http",
		Host:      host,
		ONVIFPort: subPort,
		User:      "admin",
		Password:  "pw",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Shrink short-request client timeout to 80ms; longPollClient must still succeed at 250ms!
	c.httpClient.Timeout = 80 * time.Millisecond

	events, err := c.PollEvents(context.Background(), 1)
	if err != nil {
		t.Fatalf("PollEvents failed despite longPollClient: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected 0 events, got %d", len(events))
	}
}
