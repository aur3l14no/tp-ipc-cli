package ipc

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aur3l14no/tp-ipc-cli/internal/config"
)

func TestParseONVIFPTZPosition(t *testing.T) {
	sample := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema">
  <SOAP-ENV:Body>
    <tptz:GetStatusResponse>
      <tptz:PTZStatus>
        <tt:Position>
          <tt:PanTilt x="-0.235000" y="0.410000" space="http://www.onvif.org/ver10/tptz/PanTiltSpaces/PositionGenericSpace"/>
        </tt:Position>
      </tptz:PTZStatus>
    </tptz:GetStatusResponse>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>`)

	pos, err := parseONVIFPTZPosition(sample)
	if err != nil {
		t.Fatalf("parseONVIFPTZPosition failed: %v", err)
	}
	if pos.Pan != -0.235 || pos.Tilt != 0.41 || pos.Source != "onvif" {
		t.Fatalf("unexpected PTZPosition: %+v", pos)
	}
}

func TestParsePullMessagesAndSubscription(t *testing.T) {
	subXML := []byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:wsa5="http://www.w3.org/2005/08/addressing">
  <s:Body><tev:CreatePullPointSubscriptionResponse>
    <tev:SubscriptionReference><wsa5:Address>http://192.168.1.60:2020/onvif/subscription?Idx=1</wsa5:Address></tev:SubscriptionReference>
  </tev:CreatePullPointSubscriptionResponse></s:Body></s:Envelope>`)

	addr, err := parseSubscriptionAddress(subXML)
	if err != nil {
		t.Fatalf("parseSubscriptionAddress failed: %v", err)
	}
	if addr != "http://192.168.1.60:2020/onvif/subscription?Idx=1" {
		t.Fatalf("unexpected addr %q", addr)
	}

	pullXML := []byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:tt="http://www.onvif.org/ver10/schema">
  <s:Body><tev:PullMessagesResponse>
    <wsnt:NotificationMessage>
      <wsnt:Topic>tns1:RuleEngine/CellMotionDetector/Motion</wsnt:Topic>
      <wsnt:Message><tt:Message UtcTime="2026-04-16T04:00:00Z">
        <tt:Data><tt:SimpleItem Name="IsMotion" Value="true"/></tt:Data>
      </tt:Message></wsnt:Message>
    </wsnt:NotificationMessage>
  </tev:PullMessagesResponse></s:Body></s:Envelope>`)

	events, err := parsePullMessages(pullXML)
	if err != nil {
		t.Fatalf("parsePullMessages failed: %v", err)
	}
	if len(events) != 1 || events[0].Topic != "tns1:RuleEngine/CellMotionDetector/Motion" || events[0].Data["IsMotion"] != "true" {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestWSSEEnvelopeAndRTSPDigest(t *testing.T) {
	now := time.Date(2026, 4, 16, 12, 0, 0, 0, time.UTC)
	env := buildWSSEEnvelope("admin", "secret", "<tptz:Stop/>", []byte("0123456789abcdef"), now)
	if !strings.Contains(env, "<wsu:Created>2026-04-16T12:00:00Z</wsu:Created>") || !strings.Contains(env, "PasswordDigest") {
		t.Fatalf("unexpected WSSE envelope: %s", env)
	}

	hdr, err := buildRTSPAuthHeader(
		[]string{`WWW-Authenticate: Digest realm="TP-Link IP-Camera", nonce="abcdef123456"`},
		"MULTITRANS",
		"rtsp://192.168.1.60/multitrans",
		"admin",
		"secret",
	)
	if err != nil {
		t.Fatalf("buildRTSPAuthHeader failed: %v", err)
	}
	if !strings.HasPrefix(hdr, `Digest username="admin", realm="TP-Link IP-Camera", nonce="abcdef123456"`) {
		t.Fatalf("unexpected Digest header: %s", hdr)
	}
}

func TestPTZMoveRelativeRespectsInvertFlags(t *testing.T) {
	var soapBodies []string
	onvifSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		soapBodies = append(soapBodies, string(b))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><tptz:RelativeMoveResponse/></s:Body></s:Envelope>`))
	}))
	defer onvifSrv.Close()

	_, host, onvifPort, err := config.ParseHostInput(onvifSrv.URL)
	if err != nil {
		t.Fatal(err)
	}

	c, err := NewClient(config.Settings{
		Host:       host,
		ONVIFPort:  onvifPort,
		User:       "admin",
		Password:   "pw",
		InvertPan:  true,
		InvertTilt: false,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := c.PTZMoveRelative(context.Background(), -0.05, 0.04); err != nil {
		t.Fatalf("PTZMoveRelative failed: %v", err)
	}
	if err := c.PTZMoveAbsolute(context.Background(), -0.35, 0.50); err != nil {
		t.Fatalf("PTZMoveAbsolute failed: %v", err)
	}
	if len(soapBodies) != 2 {
		t.Fatalf("expected 2 SOAP calls, got %d", len(soapBodies))
	}
	if !strings.Contains(soapBodies[0], `x="0.050000" y="0.040000"`) {
		t.Fatalf("expected inverted pan (+0.05) and unchanged tilt (+0.04) in RelativeMove, got: %s", soapBodies[0])
	}
	if !strings.Contains(soapBodies[1], `x="-0.350000" y="0.500000"`) {
		t.Fatalf("expected AbsoluteMove coordinates unchanged, got: %s", soapBodies[1])
	}

	// Verify /ds fallback also honors live SetPTZInvert updates
	var dsPan, dsTilt string
	dsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			if _, ok := body["login"]; ok {
				_ = json.NewEncoder(w).Encode(map[string]any{"error_code": 0, "stok": "tok1"})
				return
			}
			if ptz, ok := body["ptz"].(map[string]any); ok {
				if rel, ok := ptz["relative_move"].(map[string]any); ok {
					dsPan, _ = rel["translation_pan"].(string)
					dsTilt, _ = rel["translation_tilt"].(string)
				}
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"error_code": 0})
	}))
	defer dsSrv.Close()

	_, dsHost, dsPort, _ := config.ParseHostInput(dsSrv.URL)
	c2, err := NewClient(config.Settings{
		Host:      dsHost,
		HTTPPort:  dsPort,
		ONVIFPort: 1, // unreachable so it falls back to /ds
		User:      "admin",
		Password:  "pw",
	})
	if err != nil {
		t.Fatal(err)
	}
	c2.SetPTZInvert(true, true)
	if err := c2.PTZMoveRelative(context.Background(), -0.05, 0.04); err != nil {
		t.Fatalf("PTZMoveRelative /ds fallback failed: %v", err)
	}
	if dsPan != "0.050000" || dsTilt != "-0.040000" {
		t.Fatalf("expected /ds fallback pan=0.050000 tilt=-0.040000, got pan=%q tilt=%q", dsPan, dsTilt)
	}
}
