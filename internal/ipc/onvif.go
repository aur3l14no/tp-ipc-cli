package ipc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const onvifProfileToken = "profile_1"

type PTZPosition struct {
	Pan       float64 `json:"pan"`
	Tilt      float64 `json:"tilt"`
	PanState  string  `json:"pan_state,omitempty"`
	TiltState string  `json:"tilt_state,omitempty"`
	Source    string  `json:"source,omitempty"`
}

type CameraEvent struct {
	Topic   string            `json:"topic"`
	UTCTime string            `json:"utc_time,omitempty"`
	Data    map[string]string `json:"data"`
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func buildWSSEEnvelope(user, password, bodyXML string, nonce []byte, now time.Time) string {
	created := now.UTC().Format("2006-01-02T15:04:05Z")
	h := sha1.New()
	h.Write(nonce)
	h.Write([]byte(created))
	h.Write([]byte(password))
	digest := base64.StdEncoding.EncodeToString(h.Sum(nil))
	nonceB64 := base64.StdEncoding.EncodeToString(nonce)

	return `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" ` +
		`xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" ` +
		`xmlns:tev="http://www.onvif.org/ver10/events/wsdl" ` +
		`xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" ` +
		`xmlns:tt="http://www.onvif.org/ver10/schema" ` +
		`xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" ` +
		`xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">` +
		`<s:Header><wsse:Security><wsse:UsernameToken>` +
		`<wsse:Username>` + xmlEscape(user) + `</wsse:Username>` +
		`<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">` + digest + `</wsse:Password>` +
		`<wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">` + nonceB64 + `</wsse:Nonce>` +
		`<wsu:Created>` + created + `</wsu:Created>` +
		`</wsse:UsernameToken></wsse:Security></s:Header>` +
		`<s:Body>` + bodyXML + `</s:Body></s:Envelope>`
}

func (c *Client) doSOAP(ctx context.Context, action, bodyXML, endpoint string) ([]byte, error) {
	return c.doSOAPInternal(ctx, action, bodyXML, endpoint, false)
}

func (c *Client) doSOAPLongPoll(ctx context.Context, action, bodyXML, endpoint string) ([]byte, error) {
	return c.doSOAPInternal(ctx, action, bodyXML, endpoint, true)
}

func (c *Client) doSOAPInternal(ctx context.Context, action, bodyXML, endpoint string, longPoll bool) ([]byte, error) {
	if c.cfg.User == "" || c.cfg.Password == "" {
		return nil, errors.New("camera credentials missing")
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate ONVIF nonce: %w", err)
	}
	envelope := buildWSSEEnvelope(c.cfg.User, c.cfg.Password, bodyXML, nonce, time.Now())
	if endpoint == "" {
		endpoint = c.cfg.ONVIFBaseURL() + "/onvif/service"
	}
	headers := map[string]string{
		"Content-Type": fmt.Sprintf(`application/soap+xml; charset=utf-8; action=%q`, action),
		"SOAPAction":   fmt.Sprintf("%q", action),
	}
	var (
		status int
		resp   []byte
		err    error
	)
	if longPoll {
		status, resp, err = c.rawHTTPLongPoll(ctx, endpoint, http.MethodPost, []byte(envelope), headers)
	} else {
		status, resp, err = c.rawHTTP(ctx, endpoint, http.MethodPost, []byte(envelope), headers)
	}
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK || bytes.Contains(resp, []byte(":Fault>")) || bytes.Contains(resp, []byte("<Fault")) {
		reason := parseSOAPFaultReason(resp)
		if reason != "" {
			return nil, fmt.Errorf("ONVIF %s failed (HTTP %d): %s", shortAction(action), status, reason)
		}
		return nil, fmt.Errorf("ONVIF %s failed (HTTP %d)", shortAction(action), status)
	}
	return resp, nil
}

func shortAction(action string) string {
	if idx := strings.LastIndex(action, "/"); idx >= 0 && idx+1 < len(action) {
		return action[idx+1:]
	}
	return action
}

func parseSOAPFaultReason(data []byte) string {
	dec := xml.NewDecoder(bytes.NewReader(data))
	inText := false
	for {
		tok, err := dec.Token()
		if err != nil {
			return ""
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "Text" || t.Name.Local == "faultstring" {
				inText = true
			}
		case xml.CharData:
			if inText {
				s := strings.TrimSpace(string(t))
				if s != "" {
					return s
				}
			}
		case xml.EndElement:
			inText = false
		}
	}
}

func parseONVIFPTZPosition(data []byte) (PTZPosition, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	inPosition := false
	var pos PTZPosition
	found := false
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return pos, fmt.Errorf("invalid ONVIF PTZ XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "Position":
				inPosition = true
			case "PanTilt":
				if inPosition {
					var xStr, yStr string
					for _, attr := range t.Attr {
						if attr.Name.Local == "x" {
							xStr = attr.Value
						} else if attr.Name.Local == "y" {
							yStr = attr.Value
						}
					}
					x, errX := strconv.ParseFloat(xStr, 64)
					y, errY := strconv.ParseFloat(yStr, 64)
					if errX == nil && errY == nil {
						pos.Pan = x
						pos.Tilt = y
						pos.Source = "onvif"
						found = true
					}
				}
			case "PanTiltStatus", "MoveStatus":
				// optional MoveStatus child parsing handled below
			}
		case xml.EndElement:
			if t.Name.Local == "Position" {
				inPosition = false
			}
		}
	}
	if !found {
		return pos, errors.New("ONVIF PTZ GetStatus response missing Position/PanTilt")
	}
	return pos, nil
}

// PTZStatus queries current pan/tilt coordinates via ONVIF, falling back to /ds ptz.get_ptz_status if ONVIF is unreachable.
func (c *Client) PTZStatus(ctx context.Context) (PTZPosition, error) {
	resp, err := c.doSOAP(ctx,
		"http://www.onvif.org/ver20/ptz/wsdl/GetStatus",
		`<tptz:GetStatus><tptz:ProfileToken>`+onvifProfileToken+`</tptz:ProfileToken></tptz:GetStatus>`,
		"",
	)
	if err == nil {
		if pos, parseErr := parseONVIFPTZPosition(resp); parseErr == nil {
			return pos, nil
		}
	}

	dsRes, dsErr := c.ActionModule(ctx, "ptz", "get_ptz_status", nil)
	if dsErr != nil {
		if err != nil {
			return PTZPosition{}, err
		}
		return PTZPosition{}, dsErr
	}
	st := asMap(asMap(dsRes["ptz"])["status"])
	return PTZPosition{
		Pan:       jsonFloat(st["position_pan"], 0),
		Tilt:      jsonFloat(st["position_tilt"], 0),
		PanState:  jsonStr(st["status_pan"]),
		TiltState: jsonStr(st["status_tilt"]),
		Source:    "ds",
	}, nil
}

// PTZMoveRelative moves pan/tilt by normalized increments within [-maxDelta, maxDelta].
func (c *Client) PTZMoveRelative(ctx context.Context, pan, tilt float64) error {
	if math.IsNaN(pan) || math.IsInf(pan, 0) || math.IsNaN(tilt) || math.IsInf(tilt, 0) {
		return errors.New("pan and tilt must be finite numbers")
	}
	if pan < -0.25 || pan > 0.25 || tilt < -0.25 || tilt > 0.25 {
		return errors.New("relative pan/tilt step must be within [-0.25, 0.25] (use `ptz goto` for full [-1, 1] range)")
	}
	if pan == 0 && tilt == 0 {
		return errors.New("at least one of pan or tilt must be non-zero")
	}

	invertPan, invertTilt := c.PTZInvert()
	if invertPan {
		pan = -pan
	}
	if invertTilt {
		tilt = -tilt
	}

	body := fmt.Sprintf(
		`<tptz:RelativeMove><tptz:ProfileToken>%s</tptz:ProfileToken><tptz:Translation><tt:PanTilt x="%.6f" y="%.6f"/></tptz:Translation></tptz:RelativeMove>`,
		onvifProfileToken, pan, tilt,
	)
	_, err := c.doSOAP(ctx, "http://www.onvif.org/ver20/ptz/wsdl/RelativeMove", body, "")
	if err == nil {
		return nil
	}

	// Fallback to /ds ptz.relative_move when ONVIF port 2020 is unavailable (e.g. HTTP-only tunnel), clamping to ±0.05 for motor safety
	clampedPan := math.Max(-0.05, math.Min(0.05, pan))
	clampedTilt := math.Max(-0.05, math.Min(0.05, tilt))
	_, dsErr := c.ActionModule(ctx, "ptz", "relative_move", map[string]any{
		"translation_pan":  fmt.Sprintf("%.6f", clampedPan),
		"translation_tilt": fmt.Sprintf("%.6f", clampedTilt),
		"translation_zoom": "0.000000",
	})
	if dsErr != nil {
		return err
	}
	return nil
}

// PTZMoveAbsolute moves the gimbal to normalized coordinates in [-1, 1].
func (c *Client) PTZMoveAbsolute(ctx context.Context, pan, tilt float64) error {
	if math.IsNaN(pan) || math.IsInf(pan, 0) || math.IsNaN(tilt) || math.IsInf(tilt, 0) ||
		pan < -1 || pan > 1 || tilt < -1 || tilt > 1 {
		return errors.New("absolute pan and tilt must be within [-1, 1]")
	}
	body := fmt.Sprintf(
		`<tptz:AbsoluteMove><tptz:ProfileToken>%s</tptz:ProfileToken><tptz:Position><tt:PanTilt x="%.6f" y="%.6f"/></tptz:Position></tptz:AbsoluteMove>`,
		onvifProfileToken, pan, tilt,
	)
	_, err := c.doSOAP(ctx, "http://www.onvif.org/ver20/ptz/wsdl/AbsoluteMove", body, "")
	return err
}

func (c *Client) PTZStop(ctx context.Context) error {
	body := fmt.Sprintf(
		`<tptz:Stop><tptz:ProfileToken>%s</tptz:ProfileToken><tptz:PanTilt>true</tptz:PanTilt><tptz:Zoom>true</tptz:Zoom></tptz:Stop>`,
		onvifProfileToken,
	)
	if _, err := c.doSOAP(ctx, "http://www.onvif.org/ver20/ptz/wsdl/Stop", body, ""); err != nil {
		_, dsErr := c.ActionModule(ctx, "motor", "stop", "null")
		if dsErr != nil {
			return err
		}
	}
	return nil
}

func (c *Client) RemovePresetONVIF(ctx context.Context, id string) error {
	body := fmt.Sprintf(
		`<tptz:RemovePreset><tptz:ProfileToken>%s</tptz:ProfileToken><tptz:PresetToken>%s</tptz:PresetToken></tptz:RemovePreset>`,
		onvifProfileToken, xmlEscape(id),
	)
	_, err := c.doSOAP(ctx, "http://www.onvif.org/ver20/ptz/wsdl/RemovePreset", body, "")
	return err
}

func parseSubscriptionAddress(data []byte) (string, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	inSubRef := false
	inAddress := false
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "SubscriptionReference" {
				inSubRef = true
			} else if inSubRef && t.Name.Local == "Address" {
				inAddress = true
			}
		case xml.CharData:
			if inAddress {
				addr := strings.TrimSpace(string(t))
				if addr != "" {
					return addr, nil
				}
			}
		case xml.EndElement:
			if t.Name.Local == "Address" {
				inAddress = false
			} else if t.Name.Local == "SubscriptionReference" {
				inSubRef = false
			}
		}
	}
	return "", errors.New("ONVIF subscription response missing SubscriptionReference/Address")
}

func parsePullMessages(data []byte) ([]CameraEvent, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	events := make([]CameraEvent, 0)
	inNotif := false
	inTopic := false
	var cur CameraEvent

	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("invalid ONVIF PullMessages XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "NotificationMessage":
				inNotif = true
				cur = CameraEvent{Data: make(map[string]string)}
			case "Topic":
				if inNotif {
					inTopic = true
				}
			case "Message":
				if inNotif && cur.UTCTime == "" {
					for _, a := range t.Attr {
						if a.Name.Local == "UtcTime" {
							cur.UTCTime = a.Value
						}
					}
				}
			case "SimpleItem":
				if inNotif {
					var name, val string
					for _, a := range t.Attr {
						if a.Name.Local == "Name" {
							name = a.Value
						} else if a.Name.Local == "Value" {
							val = a.Value
						}
					}
					if name != "" {
						cur.Data[name] = val
					}
				}
			}
		case xml.CharData:
			if inNotif && inTopic {
				s := strings.TrimSpace(string(t))
				if s != "" {
					cur.Topic = s
				}
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "Topic":
				inTopic = false
			case "NotificationMessage":
				if inNotif {
					events = append(events, cur)
					inNotif = false
				}
			}
		}
	}
	return events, nil
}

func (c *Client) PollEvents(ctx context.Context, waitSeconds int) ([]CameraEvent, error) {
	if waitSeconds < 1 || waitSeconds > 15 {
		return nil, errors.New("wait_seconds must be between 1 and 15")
	}
	createResp, err := c.doSOAP(ctx,
		"http://www.onvif.org/ver10/events/wsdl/EventPortType/CreatePullPointSubscriptionRequest",
		`<tev:CreatePullPointSubscription><tev:InitialTerminationTime>PT60S</tev:InitialTerminationTime></tev:CreatePullPointSubscription>`,
		"",
	)
	if err != nil {
		return nil, err
	}
	subAddr, err := parseSubscriptionAddress(createResp)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(subAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid ONVIF subscription URL %q", subAddr)
	}
	// Preserve the dynamic PullPoint port (e.g. :1024) returned by the camera while using configured host
	subPort := u.Port()
	if subPort == "" {
		subPort = strconv.Itoa(c.cfg.ONVIFPort)
	}
	targetAddr := fmt.Sprintf("http://%s%s", net.JoinHostPort(c.cfg.Host, subPort), u.RequestURI())

	defer func() {
		unsubCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, _ = c.doSOAP(unsubCtx,
			"http://docs.oasis-open.org/wsn/bw-2/SubscriptionManager/UnsubscribeRequest",
			`<wsnt:Unsubscribe/>`,
			targetAddr,
		)
	}()

	pullBody := fmt.Sprintf(`<tev:PullMessages><tev:Timeout>PT%dS</tev:Timeout><tev:MessageLimit>20</tev:MessageLimit></tev:PullMessages>`, waitSeconds)
	pullCtx, cancel := context.WithTimeout(ctx, time.Duration(waitSeconds+8)*time.Second)
	defer cancel()

	pullResp, err := c.doSOAPLongPoll(pullCtx,
		"http://www.onvif.org/ver10/events/wsdl/PullPointSubscription/PullMessagesRequest",
		pullBody,
		targetAddr,
	)
	if err != nil {
		return nil, err
	}
	return parsePullMessages(pullResp)
}
