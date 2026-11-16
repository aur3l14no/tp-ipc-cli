package ipc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type ActivationState struct {
	State                 string `json:"state"`
	Username              string `json:"username"`
	Code                  int    `json:"code"`
	CredentialsConfigured bool   `json:"credentials_configured"`
}

type Capabilities struct {
	PTZ            bool `json:"ptz"`
	HumanDetection bool `json:"human_detection"`
	Tracking       bool `json:"tracking"`
	Privacy        bool `json:"privacy"`
}

type DeviceInfo struct {
	Model        string       `json:"model"`
	Hardware     string       `json:"hardware"`
	Firmware     string       `json:"firmware"`
	Alias        string       `json:"alias"`
	MAC          string       `json:"mac,omitempty"`
	DeviceName   string       `json:"device_name,omitempty"`
	Capabilities Capabilities `json:"capabilities"`
}

type DiskStatus struct {
	Name       string `json:"name,omitempty"`
	Status     string `json:"status"`
	TotalSpace string `json:"total"`
	FreeSpace  string `json:"free"`
	Percent    string `json:"percent,omitempty"`
}

type CameraStatus struct {
	Person      map[string]any `json:"person"`
	Motion      map[string]any `json:"motion"`
	Tamper      map[string]any `json:"tamper"`
	Tracking    map[string]any `json:"tracking"`
	Privacy     map[string]any `json:"privacy"`
	NightVision string         `json:"night_vision"`
	Rotation    string         `json:"rotation"`
	Alarm       map[string]any `json:"alarm"`
	LED         map[string]any `json:"led"`
	Speaker     map[string]any `json:"speaker"`
	Storage     []DiskStatus   `json:"storage"`
}

type Preset struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Pan      *float64 `json:"pan,omitempty"`
	Tilt     *float64 `json:"tilt,omitempty"`
	ReadOnly bool     `json:"read_only,omitempty"`
}

type RecordingSegment struct {
	StartUnix   int64  `json:"start_unix"`
	EndUnix     int64  `json:"end_unix"`
	StartTime   string `json:"start_time"`
	EndTime     string `json:"end_time"`
	DurationSec int64  `json:"duration_seconds"`
	VideoType   int    `json:"video_type"`
	TypeLabel   string `json:"type_label"`
}

type PersonAlarmResult struct {
	Detected       bool   `json:"detected"`
	Signal         string `json:"signal"`
	ObservedAtUnix int64  `json:"observed_at_unix,omitempty"`
}

func onOff(enabled bool) string {
	if enabled {
		return "on"
	}
	return "off"
}

func decodeMaybeEscaped(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	if u, err := url.PathUnescape(s); err == nil {
		return u
	}
	return s
}

func unwrapNamedRows(v any) []map[string]any {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(arr))
	for _, item := range arr {
		rowMap, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if len(rowMap) == 1 {
			for k, inner := range rowMap {
				if innerMap, ok := inner.(map[string]any); ok {
					cp := make(map[string]any, len(innerMap)+1)
					for ik, iv := range innerMap {
						cp[ik] = iv
					}
					if _, exists := cp["_row_key"]; !exists {
						cp["_row_key"] = k
					}
					out = append(out, cp)
					continue
				}
			}
		}
		out = append(out, rowMap)
	}
	return out
}

func (c *Client) ActivationStatus(ctx context.Context) (ActivationState, error) {
	ch, status, err := c.fetchChallenge(ctx)
	if err != nil {
		return ActivationState{}, err
	}
	if status != http.StatusUnauthorized && ch.Data.Code == 0 {
		return ActivationState{}, fmt.Errorf("camera activation status unavailable (HTTP %d)", status)
	}
	code := ch.Data.Code
	switch code {
	case ErrCodeNeedsActivation:
		return ActivationState{
			State:    "needs_activation",
			Username: "admin",
			Code:     code,
		}, nil
	case ErrCodeNeedsPassChange:
		return ActivationState{
			State:    "needs_password_change",
			Username: "admin",
			Code:     code,
		}, nil
	case ErrCodeActivated:
		return ActivationState{
			State:                 "activated",
			Username:              "admin",
			Code:                  code,
			CredentialsConfigured: c.cfg.User != "" && c.cfg.Password != "",
		}, nil
	default:
		return ActivationState{}, fmt.Errorf("unknown camera activation status code %d", code)
	}
}

func (c *Client) DeviceInfo(ctx context.Context) (DeviceInfo, error) {
	res, err := c.DoDS(ctx, map[string]any{
		"method":      "get",
		"device_info": map[string]any{"name": []string{"basic_info"}},
		"function":    map[string]any{"name": []string{"module_spec"}},
	})
	if err != nil {
		// Fallback to separate calls if firmware dislikes combined query
		devMod, err1 := c.GetModule(ctx, "device_info", "basic_info")
		if err1 != nil {
			return DeviceInfo{}, err1
		}
		fnMod, _ := c.GetModule(ctx, "function", "module_spec")
		res = map[string]any{"device_info": devMod, "function": fnMod}
	}

	basic := asMap(asMap(res["device_info"])["basic_info"])
	modules := asMap(asMap(res["function"])["module_spec"])

	return DeviceInfo{
		Model:      jsonStr(basic["device_model"]),
		Hardware:   jsonStr(basic["hw_version"]),
		Firmware:   decodeMaybeEscaped(jsonStr(basic["sw_version"])),
		Alias:      decodeMaybeEscaped(jsonStr(basic["device_alias"])),
		MAC:        jsonStr(basic["mac"]),
		DeviceName: decodeMaybeEscaped(jsonStr(basic["device_name"])),
		Capabilities: Capabilities{
			PTZ:            jsonStr(modules["ptz"]) == "1",
			HumanDetection: jsonStr(modules["smart_detection"]) == "1",
			Tracking:       jsonStr(modules["target_track"]) == "1",
			Privacy:        jsonStr(modules["lens_mask"]) == "1",
		},
	}, nil
}

func (c *Client) StorageStatus(ctx context.Context) ([]DiskStatus, error) {
	res, err := c.DoDS(ctx, map[string]any{
		"method": "get",
		"harddisk_manage": map[string]any{
			"name":  []string{"harddisk"},
			"table": []string{"hd_info"},
		},
	})
	if err != nil {
		return nil, err
	}
	hdMod := asMap(res["harddisk_manage"])
	rows := unwrapNamedRows(hdMod["hd_info"])
	disks := make([]DiskStatus, 0, len(rows))
	for _, r := range rows {
		d := DiskStatus{
			Name:       jsonStr(r["_row_key"]),
			Status:     jsonStr(r["status"]),
			TotalSpace: jsonStr(r["total_space"]),
			FreeSpace:  jsonStr(r["free_space"]),
			Percent:    jsonStr(r["percent"]),
		}
		if d.Status == "" && d.TotalSpace == "" && d.FreeSpace == "" {
			continue
		}
		disks = append(disks, d)
	}
	return disks, nil
}

func (c *Client) CameraStatus(ctx context.Context) (CameraStatus, error) {
	batchPayload := map[string]any{
		"method":            "get",
		"people_detection":  map[string]any{"name": []string{"detection"}},
		"motion_detection":  map[string]any{"name": []string{"motion_det"}},
		"tamper_detection":  map[string]any{"name": []string{"tamper_det"}},
		"target_track":      map[string]any{"name": []string{"target_track_info"}},
		"lens_mask":         map[string]any{"name": []string{"lens_mask_info"}},
		"image":             map[string]any{"name": []string{"switch"}},
		"msg_alarm":         map[string]any{"name": []string{"chn1_msg_alarm_info"}},
		"led":               map[string]any{"name": []string{"config"}},
		"audio_config":      map[string]any{"name": []string{"speaker"}},
		"harddisk_manage":   map[string]any{"name": []string{"harddisk"}, "table": []string{"hd_info"}},
	}

	res, err := c.DoDS(ctx, batchPayload)
	if err != nil {
		// Graceful per-module fallback if one module is unsupported on a variant model
		res = make(map[string]any)
		queries := [][2]string{
			{"people_detection", "detection"},
			{"motion_detection", "motion_det"},
			{"tamper_detection", "tamper_det"},
			{"target_track", "target_track_info"},
			{"lens_mask", "lens_mask_info"},
			{"image", "switch"},
			{"msg_alarm", "chn1_msg_alarm_info"},
			{"led", "config"},
			{"audio_config", "speaker"},
		}
		for _, q := range queries {
			if mod, mErr := c.GetModule(ctx, q[0], q[1]); mErr == nil {
				res[q[0]] = mod
			} else if len(res) == 0 {
				// Propagate initial auth/connectivity failure immediately
				var apiErr *APIError
				if !errors.As(mErr, &apiErr) {
					return CameraStatus{}, mErr
				}
			}
		}
	}

	imgSwitch := asMap(asMap(res["image"])["switch"])
	var disks []DiskStatus
	if hdMod, ok := res["harddisk_manage"]; ok {
		for _, r := range unwrapNamedRows(asMap(hdMod)["hd_info"]) {
			d := DiskStatus{
				Name:       jsonStr(r["_row_key"]),
				Status:     jsonStr(r["status"]),
				TotalSpace: jsonStr(r["total_space"]),
				FreeSpace:  jsonStr(r["free_space"]),
				Percent:    jsonStr(r["percent"]),
			}
			if d.Status == "" && d.TotalSpace == "" && d.FreeSpace == "" {
				continue
			}
			disks = append(disks, d)
		}
	} else if d, dErr := c.StorageStatus(ctx); dErr == nil {
		disks = d
	}

	return CameraStatus{
		Person:      asMap(asMap(res["people_detection"])["detection"]),
		Motion:      asMap(asMap(res["motion_detection"])["motion_det"]),
		Tamper:      asMap(asMap(res["tamper_detection"])["tamper_det"]),
		Tracking:    asMap(asMap(res["target_track"])["target_track_info"]),
		Privacy:     asMap(asMap(res["lens_mask"])["lens_mask_info"]),
		NightVision: jsonStr(imgSwitch["night_vision_mode"]),
		Rotation:    jsonStr(imgSwitch["rotate_type"]),
		Alarm:       asMap(asMap(res["msg_alarm"])["chn1_msg_alarm_info"]),
		LED:         asMap(asMap(res["led"])["config"]),
		Speaker:     asMap(asMap(res["audio_config"])["speaker"]),
		Storage:     disks,
	}, nil
}

func asStringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, len(arr))
	for i, x := range arr {
		out[i] = jsonStr(x)
	}
	return out
}

func (c *Client) ListPresets(ctx context.Context) ([]Preset, map[string]any, error) {
	mod, err := c.GetModule(ctx, "preset", "preset")
	if err != nil {
		return nil, nil, err
	}
	rawSection := mod["preset"]
	rawMap := asMap(rawSection)

	// Format A: parallel arrays {"id": ["1","2"], "name": ["Desk","Door"], "position_pan": [...], "position_tilt": [...], "read_only": [...]}
	ids := asStringSlice(rawMap["id"])
	names := asStringSlice(rawMap["name"])
	pans := asStringSlice(rawMap["position_pan"])
	tilts := asStringSlice(rawMap["position_tilt"])
	readOnly := asStringSlice(rawMap["read_only"])
	if len(ids) > 0 {
		presets := make([]Preset, 0, len(ids))
		for i, id := range ids {
			p := Preset{ID: id}
			if i < len(names) {
				p.Name = decodeMaybeEscaped(names[i])
			}
			if i < len(pans) {
				if v, err := strconv.ParseFloat(pans[i], 64); err == nil {
					p.Pan = &v
				}
			}
			if i < len(tilts) {
				if v, err := strconv.ParseFloat(tilts[i], 64); err == nil {
					p.Tilt = &v
				}
			}
			if i < len(readOnly) {
				p.ReadOnly = readOnly[i] == "1" || strings.EqualFold(readOnly[i], "true")
			}
			presets = append(presets, p)
		}
		return presets, rawMap, nil
	}

	// Format B: array of named row maps
	rows := unwrapNamedRows(rawSection)
	presets := make([]Preset, 0, len(rows))
	for _, r := range rows {
		p := Preset{
			ID:       jsonStr(r["id"]),
			Name:     decodeMaybeEscaped(jsonStr(r["name"])),
			ReadOnly: jsonStr(r["read_only"]) == "1",
		}
		if v, err := strconv.ParseFloat(jsonStr(r["position_pan"]), 64); err == nil {
			p.Pan = &v
		}
		if v, err := strconv.ParseFloat(jsonStr(r["position_tilt"]), 64); err == nil {
			p.Tilt = &v
		}
		if p.ID != "" || p.Name != "" {
			presets = append(presets, p)
		}
	}
	return presets, rawMap, nil
}

var digitsOnlyRe = regexp.MustCompile(`^[0-9]{1,16}$`)

func validatePresetID(id string) error {
	if !digitsOnlyRe.MatchString(id) {
		return fmt.Errorf("invalid preset ID %q (must be 1-16 digits)", id)
	}
	return nil
}

func (c *Client) SavePreset(ctx context.Context, name string) (map[string]any, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" || len(trimmed) > 32 {
		return nil, errors.New("preset name must be 1..32 UTF-8 bytes")
	}
	return c.ActionModule(ctx, "preset", "set_preset", map[string]any{
		"name":     trimmed,
		"save_ptz": "1",
	})
}

func (c *Client) GotoPreset(ctx context.Context, id string) (map[string]any, error) {
	if err := validatePresetID(id); err != nil {
		return nil, err
	}
	return c.ActionModule(ctx, "preset", "goto_preset", map[string]any{"id": id})
}

func (c *Client) RemovePreset(ctx context.Context, id string) error {
	if err := validatePresetID(id); err != nil {
		return err
	}
	if err := c.RemovePresetONVIF(ctx, id); err == nil {
		return nil
	} else {
		if _, dsErr := c.ActionModule(ctx, "preset", "remove_preset", map[string]any{"id": []string{id}}); dsErr == nil {
			return nil
		}
		return err
	}
}

func (c *Client) SetPrivacy(ctx context.Context, enabled bool) (map[string]any, error) {
	return c.SetModule(ctx, "lens_mask", "lens_mask_info", map[string]any{"enabled": onOff(enabled)})
}

func (c *Client) SetLED(ctx context.Context, enabled bool) (map[string]any, error) {
	return c.SetModule(ctx, "led", "config", map[string]any{"enabled": onOff(enabled)})
}

func (c *Client) SetSpeakerVolume(ctx context.Context, volume int) (map[string]any, error) {
	if volume < 0 || volume > 100 {
		return nil, errors.New("speaker volume must be between 0 and 100")
	}
	return c.SetModule(ctx, "audio_config", "speaker", map[string]any{"volume": strconv.Itoa(volume)})
}

func (c *Client) SetTracking(ctx context.Context, enabled bool) (map[string]any, error) {
	return c.SetModule(ctx, "target_track", "target_track_info", map[string]any{"enabled": onOff(enabled)})
}

func (c *Client) SetDetection(ctx context.Context, kind string, enabled bool) (map[string]any, error) {
	val := map[string]any{"enabled": onOff(enabled)}
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "person", "human", "people":
		return c.SetModule(ctx, "people_detection", "detection", val)
	case "motion":
		return c.SetModule(ctx, "motion_detection", "motion_det", val)
	case "tamper":
		return c.SetModule(ctx, "tamper_detection", "tamper_det", val)
	default:
		return nil, fmt.Errorf("unknown detector %q (expected person, motion, or tamper)", kind)
	}
}

func NormalizeNightVisionMode(mode string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "ir", "infrared", "inf_night_vision":
		return "inf_night_vision", nil
	case "color", "white", "wtl", "wtl_night_vision":
		return "wtl_night_vision", nil
	case "smart", "auto", "motion", "md", "md_night_vision":
		return "md_night_vision", nil
	default:
		return "", fmt.Errorf("invalid night vision mode %q (expected ir/inf_night_vision, color/wtl_night_vision, or smart/md_night_vision)", mode)
	}
}

func (c *Client) SetNightVision(ctx context.Context, mode string) (map[string]any, error) {
	canonical, err := NormalizeNightVisionMode(mode)
	if err != nil {
		return nil, err
	}
	return c.SetModule(ctx, "image", "switch", map[string]any{"night_vision_mode": canonical})
}

func (c *Client) TriggerAlarm(ctx context.Context, seconds int) error {
	if seconds < 1 || seconds > 5 {
		return errors.New("alarm duration must be between 1 and 5 seconds")
	}
	if _, err := c.ActionModule(ctx, "msg_alarm", "manual_msg_alarm", map[string]any{"action": "start"}); err != nil {
		return err
	}
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = c.StopAlarm(stopCtx)
	}()

	timer := time.NewTimer(time.Duration(seconds) * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
	}
	return c.StopAlarm(ctx)
}

func (c *Client) StopAlarm(ctx context.Context) error {
	_, err := c.ActionModule(ctx, "msg_alarm", "manual_msg_alarm", map[string]any{"action": "stop"})
	return err
}

func (c *Client) WaitPersonAlarm(ctx context.Context, waitSeconds int) (PersonAlarmResult, error) {
	if waitSeconds < 1 || waitSeconds > 30 {
		return PersonAlarmResult{}, errors.New("wait_seconds must be between 1 and 30")
	}

	detMod, err := c.GetModule(ctx, "people_detection", "detection", "notify_list")
	if err != nil {
		return PersonAlarmResult{}, err
	}
	detector := asMap(detMod["detection"])
	if jsonStr(detector["enabled"]) != "on" {
		return PersonAlarmResult{}, errors.New("person detection is currently disabled on the camera")
	}
	personNotif := asMap(detMod["notify_list"])

	motMod, err := c.GetModule(ctx, "motion_detection", "motion_notif_list")
	if err != nil {
		return PersonAlarmResult{}, err
	}
	motionNotif := asMap(motMod["motion_notif_list"])

	if jsonStr(personNotif["sound_alarm_enabled"]) == "on" || jsonStr(motionNotif["sound_alarm_enabled"]) == "on" {
		return PersonAlarmResult{}, errors.New("sound alarm linkage must be off for silent person monitoring")
	}

	otherLinkages := [][2]string{
		{"tamper_detection", "tamper_notif_list"},
		{"linecrossing_detection", "notify_list"},
		{"intrusion_detection", "notify_list"},
		{"regionexiting_detection", "notify_list"},
		{"cry_detection", "notify_list"},
		{"unusual_detection", "login_error"},
	}
	for _, pair := range otherLinkages {
		mod, mErr := c.GetModule(ctx, pair[0], pair[1])
		if mErr != nil {
			continue
		}
		lk := asMap(mod[pair[1]])
		if jsonStr(lk["light_alarm_enabled"]) == "on" {
			return PersonAlarmResult{}, fmt.Errorf("%s also triggers white-light alarm; cannot isolate person signal", pair[0])
		}
		if jsonStr(lk["sound_alarm_enabled"]) == "on" {
			return PersonAlarmResult{}, fmt.Errorf("%s sound linkage must be off for silent monitoring", pair[0])
		}
	}

	origMotionLight := jsonStr(motionNotif["light_alarm_enabled"])
	if origMotionLight == "" {
		origMotionLight = "off"
	}
	origPersonLight := jsonStr(personNotif["light_alarm_enabled"])
	if origPersonLight == "" {
		origPersonLight = "off"
	}

	changedMotion := false
	changedPerson := false
	defer func() {
		rCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if changedPerson {
			_, _ = c.SetModule(rCtx, "people_detection", "notify_list", map[string]any{"light_alarm_enabled": origPersonLight})
		}
		if changedMotion {
			_, _ = c.SetModule(rCtx, "motion_detection", "motion_notif_list", map[string]any{"light_alarm_enabled": origMotionLight})
		}
	}()

	if origMotionLight != "off" {
		if _, err := c.SetModule(ctx, "motion_detection", "motion_notif_list", map[string]any{"light_alarm_enabled": "off"}); err != nil {
			return PersonAlarmResult{}, err
		}
		changedMotion = true
	}
	if origPersonLight != "on" {
		if _, err := c.SetModule(ctx, "people_detection", "notify_list", map[string]any{"light_alarm_enabled": "on"}); err != nil {
			return PersonAlarmResult{}, err
		}
		changedPerson = true
	}

	deadline := time.Now().Add(time.Duration(waitSeconds) * time.Second)
	res := PersonAlarmResult{
		Detected: false,
		Signal:   "person_only_white_light",
	}
	for time.Now().Before(deadline) {
		imgMod, err := c.GetModule(ctx, "image", "light_status")
		if err != nil {
			return res, err
		}
		if jsonStr(asMap(imgMod["light_status"])["wl_status"]) == "blink" {
			res.Detected = true
			res.ObservedAtUnix = time.Now().Unix()
			return res, nil
		}
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		case <-time.After(150 * time.Millisecond):
		}
	}
	return res, nil
}

// RecordingDates returns YYYY-MM-DD dates in the specified month ("YYYY-MM" or "YYYY-MM-DD") that have SD card recordings.
func (c *Client) RecordingDates(ctx context.Context, monthOrDate string) ([]string, error) {
	trimmed := strings.TrimSpace(monthOrDate)
	if trimmed == "" {
		trimmed = time.Now().Format("2006-01")
	}
	parts := strings.Split(trimmed, "-")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid month %q (expected YYYY-MM)", monthOrDate)
	}
	year, errY := strconv.Atoi(parts[0])
	month, errM := strconv.Atoi(parts[1])
	if errY != nil || errM != nil || year < 2000 || year > 2100 || month < 1 || month > 12 {
		return nil, fmt.Errorf("invalid month %q (expected YYYY-MM)", monthOrDate)
	}
	firstDay := time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.Local)
	lastDay := firstDay.AddDate(0, 1, -1).Day()
	prefix := fmt.Sprintf("%04d%02d", year, month)

	res, err := c.DoDS(ctx, map[string]any{
		"method": "do",
		"playback": map[string]any{
			"search_year_utility": map[string]any{
				"channel":    []int{0},
				"start_date": prefix + "01",
				"end_date":   fmt.Sprintf("%s%02d", prefix, lastDay),
			},
		},
	})
	if err != nil {
		return nil, err
	}

	rows := unwrapNamedRows(asMap(res["playback"])["search_results"])
	seen := make(map[string]struct{})
	dates := make([]string, 0, len(rows))
	for _, r := range rows {
		d := jsonStr(r["date"])
		if len(d) == 8 && digitsOnlyRe.MatchString(d) {
			formatted := d[0:4] + "-" + d[4:6] + "-" + d[6:8]
			if _, ok := seen[formatted]; !ok {
				seen[formatted] = struct{}{}
				dates = append(dates, formatted)
			}
		}
	}
	sort.Strings(dates)
	return dates, nil
}

func describeVideoType(v int) string {
	switch v {
	case 1:
		return "scheduled"
	case 2:
		return "motion"
	case 4:
		return "alarm"
	case 6, 16:
		return "smart_detection"
	default:
		return fmt.Sprintf("type_%d", v)
	}
}

// ListRecordings queries SD card recording segments for a given date ("YYYY-MM-DD" or "YYYYMMDD").
func (c *Client) ListRecordings(ctx context.Context, date string) ([]RecordingSegment, error) {
	trimmed := strings.TrimSpace(date)
	if trimmed == "" {
		trimmed = time.Now().Format("2006-01-02")
	}
	compact := strings.ReplaceAll(trimmed, "-", "")
	if len(compact) != 8 || !digitsOnlyRe.MatchString(compact) {
		return nil, fmt.Errorf("invalid date %q (expected YYYY-MM-DD)", date)
	}
	if _, err := time.Parse("20060102", compact); err != nil {
		return nil, fmt.Errorf("invalid calendar date %q: %w", date, err)
	}

	res, err := c.DoDSWithUserID(ctx, func(userID int) any {
		return map[string]any{
			"method": "do",
			"playback": map[string]any{
				"search_video_utility": map[string]any{
					"channel":     0,
					"date":        compact,
					"start_index": 0,
					"end_index":   999,
					"id":          userID,
				},
			},
		}
	})
	if err != nil {
		return nil, err
	}

	rows := unwrapNamedRows(asMap(res["playback"])["search_video_results"])
	segments := make([]RecordingSegment, 0, len(rows))
	for _, r := range rows {
		startUnix := int64(jsonInt(r["startTime"], 0))
		endUnix := int64(jsonInt(r["endTime"], 0))
		vType := jsonInt(r["vedio_type"], jsonInt(r["video_type"], 0))
		if startUnix <= 0 || endUnix <= 0 || endUnix < startUnix {
			continue
		}
		segments = append(segments, RecordingSegment{
			StartUnix:   startUnix,
			EndUnix:     endUnix,
			StartTime:   time.Unix(startUnix, 0).In(time.Local).Format(time.RFC3339),
			EndTime:     time.Unix(endUnix, 0).In(time.Local).Format(time.RFC3339),
			DurationSec: endUnix - startUnix,
			VideoType:   vType,
			TypeLabel:   describeVideoType(vType),
		})
	}
	sort.Slice(segments, func(i, j int) bool {
		return segments[i].StartUnix < segments[j].StartUnix
	})
	return segments, nil
}
