package ipc

import (
	"strings"
	"testing"
	"time"
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
