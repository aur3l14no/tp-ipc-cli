package mcp

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aur3l14no/tp-ipc-cli/internal/config"
	"github.com/aur3l14no/tp-ipc-cli/internal/ipc"
)

const ServerVersion = "0.3.3"

type Server struct {
	overrides config.Overrides
	clients   map[config.Settings]*ipc.Client
}

func NewServer(ov config.Overrides) *Server {
	return &Server{
		overrides: ov,
		clients:   make(map[config.Settings]*ipc.Client),
	}
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type toolSchema struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

func makeGlobalTool(name, desc string, props map[string]any, required ...string) toolSchema {
	if props == nil {
		props = map[string]any{}
	}
	req := required
	if req == nil {
		req = []string{}
	}
	return toolSchema{
		Name:        name,
		Description: desc,
		InputSchema: map[string]any{
			"type":                 "object",
			"properties":           props,
			"required":             req,
			"additionalProperties": false,
		},
	}
}

func makeCameraTool(name, desc string, props map[string]any, required ...string) toolSchema {
	merged := map[string]any{
		"camera": map[string]any{
			"type":        "string",
			"description": "Optional camera profile name (from camera_list). Omit to use the default camera.",
		},
	}
	for k, v := range props {
		merged[k] = v
	}
	return makeGlobalTool(name, desc, merged, required...)
}

func Tools() []toolSchema {
	boolProp := map[string]any{"type": "boolean"}
	return []toolSchema{
		makeGlobalTool("camera_list", "List all configured camera profiles, their addresses, and which profile is the default.", nil),
		makeGlobalTool("camera_discover", "Discover ONVIF / TP-LINK IPC cameras via L2 WS-Discovery multicast or across a routed VLAN CIDR block.",
			map[string]any{
				"timeout_seconds": map[string]any{"type": "integer", "minimum": 1, "maximum": 10},
				"cidr":            map[string]any{"type": "string", "description": "Optional IPv4 CIDR block for cross-VLAN discovery (e.g. 192.168.1.0/24)"},
			}),
		makeCameraTool("camera_activation_status", "Read whether the camera needs first-time activation. Requires only a camera address and does not modify the device.", nil),
		makeCameraTool("camera_info", "Read camera model, hardware/firmware version, alias, and supported local capabilities.", nil),
		makeCameraTool("camera_status", "Read current person/motion/tamper detection, tracking, privacy mask, night vision, alarm, LED, speaker, and SD card storage status.", nil),
		makeCameraTool("camera_events", "Wait briefly for ONVIF motion or tamper events (1-15s). Firmware exposes motion/tamper via ONVIF.",
			map[string]any{
				"wait_seconds": map[string]any{"type": "integer", "minimum": 1, "maximum": 15},
			}),
		makeCameraTool("camera_person_alarm", "Wait for the camera's person-only white-light alarm status (1-30s). Temporarily isolates person light linkage with sound off and restores settings afterward.",
			map[string]any{
				"wait_seconds": map[string]any{"type": "integer", "minimum": 1, "maximum": 30},
			}),
		makeCameraTool("camera_snapshot", "Capture one current RTSP JPEG frame. Optional 4K main-stream quality and 1-5x digital crop; focus_x/focus_y are [0,1] crop centers.",
			map[string]any{
				"high_quality": boolProp,
				"zoom":         map[string]any{"type": "integer", "minimum": 1, "maximum": 5},
				"focus_x":      map[string]any{"type": "number", "minimum": 0, "maximum": 1},
				"focus_y":      map[string]any{"type": "number", "minimum": 0, "maximum": 1},
			}),
		makeCameraTool("camera_record_clip", "Record a short local MKV clip directly from RTSP without video transcoding (1-20s). Requires IPC_MEDIA_DIR and ffmpeg.",
			map[string]any{
				"seconds":      map[string]any{"type": "integer", "minimum": 1, "maximum": 20},
				"high_quality": boolProp,
			}, "seconds"),
		makeCameraTool("camera_play_audio", "Play an audio file from IPC_AUDIO_DIR through the camera speaker via RTSP MULTITRANS talkback.",
			map[string]any{
				"filename": map[string]any{"type": "string"},
			}, "filename"),
		makeCameraTool("camera_alarm", "Sound the camera's manual alarm for 1-5 seconds and automatically stop it.",
			map[string]any{
				"seconds": map[string]any{"type": "integer", "minimum": 1, "maximum": 5},
			}, "seconds"),
		makeCameraTool("camera_stop_alarm", "Stop the camera's manual alarm immediately.", nil),
		makeCameraTool("camera_ptz_status", "Read current normalized pan and tilt coordinates in [-1, 1].", nil),
		makeCameraTool("camera_move", "Move pan and tilt by relative normalized steps in [-0.25, 0.25].",
			map[string]any{
				"pan":  map[string]any{"type": "number", "minimum": -0.25, "maximum": 0.25},
				"tilt": map[string]any{"type": "number", "minimum": -0.25, "maximum": 0.25},
			}, "pan", "tilt"),
		makeCameraTool("camera_go_to_position", "Move the camera to absolute normalized pan and tilt coordinates in [-1, 1].",
			map[string]any{
				"pan":  map[string]any{"type": "number", "minimum": -1, "maximum": 1},
				"tilt": map[string]any{"type": "number", "minimum": -1, "maximum": 1},
			}, "pan", "tilt"),
		makeCameraTool("camera_ptz_stop", "Stop ongoing pan/tilt gimbal movement immediately.", nil),
		makeCameraTool("camera_presets", "List saved PTZ presets on the camera.", nil),
		makeCameraTool("camera_save_preset", "Save the camera's current pan/tilt position as a named preset.",
			map[string]any{
				"name": map[string]any{"type": "string", "maxLength": 32},
			}, "name"),
		makeCameraTool("camera_go_to_preset", "Move camera to a saved preset ID.",
			map[string]any{
				"id": map[string]any{"type": "string"},
			}, "id"),
		makeCameraTool("camera_remove_preset", "Delete a saved preset by ID.",
			map[string]any{
				"id": map[string]any{"type": "string"},
			}, "id"),
		makeCameraTool("camera_set_privacy", "Enable or disable physical lens privacy mask.",
			map[string]any{"enabled": boolProp}, "enabled"),
		makeCameraTool("camera_set_led", "Enable or disable the camera status LED.",
			map[string]any{"enabled": boolProp}, "enabled"),
		makeCameraTool("camera_set_speaker_volume", "Set the camera speaker volume (0-100).",
			map[string]any{
				"volume": map[string]any{"type": "integer", "minimum": 0, "maximum": 100},
			}, "volume"),
		makeCameraTool("camera_set_tracking", "Enable or disable on-device target tracking.",
			map[string]any{"enabled": boolProp}, "enabled"),
		makeCameraTool("camera_set_detection", "Enable or disable an on-device detector (person, motion, or tamper).",
			map[string]any{
				"kind":    map[string]any{"type": "string", "enum": []string{"person", "motion", "tamper"}},
				"enabled": boolProp,
			}, "kind", "enabled"),
		makeCameraTool("camera_set_night_vision", "Set night vision mode (inf_night_vision / ir, wtl_night_vision / color, or md_night_vision / smart).",
			map[string]any{
				"mode": map[string]any{"type": "string", "enum": []string{"inf_night_vision", "wtl_night_vision", "md_night_vision", "ir", "color", "smart"}},
			}, "mode"),
		makeCameraTool("camera_recording_dates", "List YYYY-MM-DD dates in a month (YYYY-MM) that contain SD card recordings.",
			map[string]any{
				"month": map[string]any{"type": "string", "description": "Month in YYYY-MM format (defaults to current month)"},
			}),
		makeCameraTool("camera_recordings", "List SD card video recording segments on a given date (YYYY-MM-DD).",
			map[string]any{
				"date": map[string]any{"type": "string", "description": "Date in YYYY-MM-DD format (defaults to today)"},
			}),
		makeCameraTool("camera_download_recording", "Download historical SD card video across a time range (e.g. start='12:00', end='12:10') into a lossless MP4 inside IPC_MEDIA_DIR.",
			map[string]any{
				"start": map[string]any{"type": "string", "description": "Start time (HH:MM, HH:MM:SS, 'YYYY-MM-DD HH:MM:SS', or RFC3339)"},
				"end":   map[string]any{"type": "string", "description": "End time (HH:MM, HH:MM:SS, 'YYYY-MM-DD HH:MM:SS', or RFC3339)"},
				"date":  map[string]any{"type": "string", "description": "Optional YYYY-MM-DD date when start/end are HH:MM[:SS]"},
			}, "start", "end"),
	}
}

type scanEvent struct {
	line string
	err  error
	eof  bool
}

func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	done := make(chan struct{})
	defer close(done)

	events := make(chan scanEvent)
	go func() {
		scanner := bufio.NewScanner(in)
		scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
		for scanner.Scan() {
			ev := scanEvent{line: scanner.Text()}
			select {
			case events <- ev:
			case <-done:
				return
			}
		}
		select {
		case events <- scanEvent{err: scanner.Err(), eof: true}:
		case <-done:
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev := <-events:
			if ev.eof {
				return ev.err
			}
			line := strings.TrimSpace(ev.line)
			if line == "" {
				continue
			}

			var req rpcRequest
			if err := json.Unmarshal([]byte(line), &req); err != nil {
				continue
			}
			if req.Method == "" {
				continue
			}
			if len(req.ID) == 0 || string(req.ID) == "null" {
				continue
			}

			resp := s.handleRequest(ctx, req)
			encoded, err := json.Marshal(resp)
			if err != nil {
				continue
			}
			encoded = append(encoded, '\n')
			if _, err := out.Write(encoded); err != nil {
				return err
			}
		}
	}
}

func (s *Server) resolveClient(cameraArg string) (*ipc.Client, error) {
	ov := s.overrides
	ov.PasswordStdin = false // stdin belongs to JSON-RPC in MCP mode
	if cam := strings.TrimSpace(cameraArg); cam != "" {
		if cam != strings.TrimSpace(s.overrides.Camera) {
			// Explicit tool-level camera selection targets that named profile rather than single-host CLI overrides
			ov.Host = ""
			ov.HTTPPort = 0
			ov.RTSPPort = 0
			ov.ONVIFPort = 0
			ov.User = ""
			ov.PasswordFile = ""
		}
		ov.Camera = cam
	}

	cfg, err := config.Load(ov)
	if err != nil {
		return nil, err
	}
	if c, ok := s.clients[cfg]; ok {
		return c, nil
	}
	c, err := ipc.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	s.clients[cfg] = c
	return c, nil
}

func (s *Server) redactAll(msg string) string {
	out := msg
	for _, cl := range s.clients {
		out = cl.Redact(out)
	}
	return out
}

func (s *Server) handleRequest(ctx context.Context, req rpcRequest) rpcResponse {
	switch req.Method {
	case "initialize":
		var params struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &params)
		version := "2025-11-25"
		switch params.ProtocolVersion {
		case "2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25":
			version = params.ProtocolVersion
		}
		return rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"protocolVersion": version,
				"capabilities": map[string]any{
					"tools": map[string]any{"listChanged": false},
				},
				"serverInfo": map[string]any{
					"name":    "tp-ipc",
					"version": ServerVersion,
				},
			},
		}

	case "ping":
		return rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  map[string]any{},
		}

	case "tools/list":
		return rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"tools": Tools(),
			},
		}

	case "tools/call":
		var params struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil || params.Name == "" {
			return rpcResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &rpcError{Code: -32602, Message: "invalid tools/call params"},
			}
		}
		if params.Arguments == nil {
			params.Arguments = map[string]any{}
		}
		result, err := s.callTool(ctx, params.Name, params.Arguments)
		if err != nil {
			return rpcResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: map[string]any{
					"content": []map[string]any{{"type": "text", "text": s.redactAll(err.Error())}},
					"isError": true,
				},
			}
		}
		return rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  result,
		}

	default:
		return rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &rpcError{Code: -32601, Message: "method not found"},
		}
	}
}

func textResult(v any) (map[string]any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": string(b)},
		},
	}, nil
}

func (s *Server) callTool(ctx context.Context, name string, args map[string]any) (map[string]any, error) {
	switch name {
	case "camera_list":
		st, err := config.LoadStore()
		if err != nil {
			return nil, err
		}
		cams := st.Summaries()
		return textResult(map[string]any{
			"default_camera": st.DefaultCamera,
			"count":          len(cams),
			"cameras":        cams,
		})

	case "camera_discover":
		waitSec := argInt(args, "timeout_seconds", 2)
		cidr, _ := args["cidr"].(string)
		var (
			found []ipc.DiscoveredCamera
			err   error
		)
		if strings.TrimSpace(cidr) != "" {
			found, err = ipc.DiscoverCIDR(ctx, cidr, time.Duration(waitSec)*time.Second)
		} else {
			found, err = ipc.DiscoverLAN(ctx, time.Duration(waitSec)*time.Second)
		}
		if err != nil {
			return nil, err
		}
		return textResult(map[string]any{
			"count":   len(found),
			"devices": found,
		})
	}

	camName, _ := args["camera"].(string)
	client, err := s.resolveClient(camName)
	if err != nil {
		return nil, err
	}

	switch name {
	case "camera_activation_status":
		res, err := client.ActivationStatus(ctx)
		if err != nil {
			return nil, err
		}
		return textResult(res)

	case "camera_info":
		res, err := client.DeviceInfo(ctx)
		if err != nil {
			return nil, err
		}
		return textResult(res)

	case "camera_status":
		res, err := client.CameraStatus(ctx)
		if err != nil {
			return nil, err
		}
		return textResult(res)

	case "camera_events":
		waitSec := argInt(args, "wait_seconds", 5)
		res, err := client.PollEvents(ctx, waitSec)
		if err != nil {
			return nil, err
		}
		return textResult(res)

	case "camera_person_alarm":
		waitSec := argInt(args, "wait_seconds", 10)
		res, err := client.WaitPersonAlarm(ctx, waitSec)
		if err != nil {
			return nil, err
		}
		return textResult(res)

	case "camera_snapshot":
		opts := ipc.SnapshotOptions{
			HighQuality: argBool(args, "high_quality", false),
			Zoom:        argInt(args, "zoom", 1),
			FocusX:      argFloat(args, "focus_x", 0.5),
			FocusY:      argFloat(args, "focus_y", 0.5),
		}
		jpegBytes, err := client.Snapshot(ctx, opts)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"content": []map[string]any{
				{
					"type":     "image",
					"data":     base64.StdEncoding.EncodeToString(jpegBytes),
					"mimeType": "image/jpeg",
				},
			},
		}, nil

	case "camera_record_clip":
		sec, ok := argIntRequired(args, "seconds")
		if !ok || sec < 1 || sec > 20 {
			return nil, errors.New("seconds is required and must be 1..20")
		}
		res, err := client.RecordClip(ctx, sec, argBool(args, "high_quality", false), "", "")
		if err != nil {
			return nil, err
		}
		return textResult(res)

	case "camera_play_audio":
		fn, ok := argStringRequired(args, "filename")
		if !ok {
			return nil, errors.New("filename is required")
		}
		res, err := client.PlayAudioFromDir(ctx, "", fn)
		if err != nil {
			return nil, err
		}
		return textResult(res)

	case "camera_alarm":
		sec, ok := argIntRequired(args, "seconds")
		if !ok {
			return nil, errors.New("seconds is required")
		}
		if err := client.TriggerAlarm(ctx, sec); err != nil {
			return nil, err
		}
		return textResult(map[string]any{"triggered": true, "seconds": sec, "stopped": true})

	case "camera_stop_alarm":
		if err := client.StopAlarm(ctx); err != nil {
			return nil, err
		}
		return textResult(map[string]any{"stopped": true})

	case "camera_ptz_status":
		pos, err := client.PTZStatus(ctx)
		if err != nil {
			return nil, err
		}
		return textResult(pos)

	case "camera_move":
		pan, okP := argFloatRequired(args, "pan")
		tilt, okT := argFloatRequired(args, "tilt")
		if !okP || !okT {
			return nil, errors.New("pan and tilt are required")
		}
		if err := client.PTZMoveRelative(ctx, pan, tilt); err != nil {
			return nil, err
		}
		return textResult(map[string]any{"moved": true})

	case "camera_go_to_position":
		pan, okP := argFloatRequired(args, "pan")
		tilt, okT := argFloatRequired(args, "tilt")
		if !okP || !okT {
			return nil, errors.New("pan and tilt are required")
		}
		if err := client.PTZMoveAbsolute(ctx, pan, tilt); err != nil {
			return nil, err
		}
		return textResult(map[string]any{"moved": true})

	case "camera_ptz_stop":
		if err := client.PTZStop(ctx); err != nil {
			return nil, err
		}
		return textResult(map[string]any{"stopped": true})

	case "camera_presets":
		presets, raw, err := client.ListPresets(ctx)
		if err != nil {
			return nil, err
		}
		return textResult(map[string]any{"presets": presets, "raw": raw})

	case "camera_save_preset":
		presetName, ok := argStringRequired(args, "name")
		if !ok {
			return nil, errors.New("name is required")
		}
		res, err := client.SavePreset(ctx, presetName)
		if err != nil {
			return nil, err
		}
		return textResult(res)

	case "camera_go_to_preset":
		id, ok := argStringRequired(args, "id")
		if !ok {
			return nil, errors.New("id is required")
		}
		res, err := client.GotoPreset(ctx, id)
		if err != nil {
			return nil, err
		}
		return textResult(res)

	case "camera_remove_preset":
		id, ok := argStringRequired(args, "id")
		if !ok {
			return nil, errors.New("id is required")
		}
		if err := client.RemovePreset(ctx, id); err != nil {
			return nil, err
		}
		return textResult(map[string]any{"removed": true, "id": id})

	case "camera_set_privacy":
		enabled, ok := argBoolRequired(args, "enabled")
		if !ok {
			return nil, errors.New("enabled boolean is required")
		}
		res, err := client.SetPrivacy(ctx, enabled)
		if err != nil {
			return nil, err
		}
		return textResult(res)

	case "camera_set_led":
		enabled, ok := argBoolRequired(args, "enabled")
		if !ok {
			return nil, errors.New("enabled boolean is required")
		}
		res, err := client.SetLED(ctx, enabled)
		if err != nil {
			return nil, err
		}
		return textResult(res)

	case "camera_set_speaker_volume":
		vol, ok := argIntRequired(args, "volume")
		if !ok {
			return nil, errors.New("volume integer is required")
		}
		res, err := client.SetSpeakerVolume(ctx, vol)
		if err != nil {
			return nil, err
		}
		return textResult(res)

	case "camera_set_tracking":
		enabled, ok := argBoolRequired(args, "enabled")
		if !ok {
			return nil, errors.New("enabled boolean is required")
		}
		res, err := client.SetTracking(ctx, enabled)
		if err != nil {
			return nil, err
		}
		return textResult(res)

	case "camera_set_detection":
		kind, okK := argStringRequired(args, "kind")
		enabled, okE := argBoolRequired(args, "enabled")
		if !okK || !okE {
			return nil, errors.New("kind and enabled are required")
		}
		res, err := client.SetDetection(ctx, kind, enabled)
		if err != nil {
			return nil, err
		}
		return textResult(res)

	case "camera_set_night_vision":
		mode, ok := argStringRequired(args, "mode")
		if !ok {
			return nil, errors.New("mode is required")
		}
		res, err := client.SetNightVision(ctx, mode)
		if err != nil {
			return nil, err
		}
		return textResult(res)

	case "camera_recording_dates":
		month, _ := args["month"].(string)
		dates, err := client.RecordingDates(ctx, month)
		if err != nil {
			return nil, err
		}
		return textResult(map[string]any{"dates": dates, "count": len(dates)})

	case "camera_recordings":
		date, _ := args["date"].(string)
		segs, err := client.ListRecordings(ctx, date)
		if err != nil {
			return nil, err
		}
		return textResult(map[string]any{"segments": segs, "count": len(segs)})

	case "camera_download_recording":
		startVal, okS := argStringRequired(args, "start")
		endVal, okE := argStringRequired(args, "end")
		if !okS || !okE {
			return nil, errors.New("start and end are required")
		}
		dateVal, _ := args["date"].(string)
		res, err := client.DownloadRecording(ctx, ipc.ExportRecordingOptions{
			Date:  dateVal,
			Start: startVal,
			End:   endVal,
		})
		if err != nil {
			return nil, err
		}
		return textResult(res)

	default:
		return nil, fmt.Errorf("unknown tool %q", name)
	}
}

func argBool(m map[string]any, key string, fallback bool) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return fallback
}

func argBoolRequired(m map[string]any, key string) (bool, bool) {
	v, ok := m[key].(bool)
	return v, ok
}

func argInt(m map[string]any, key string, fallback int) int {
	if v, ok := argIntRequired(m, key); ok {
		return v
	}
	return fallback
}

func argIntRequired(m map[string]any, key string) (int, bool) {
	raw, exists := m[key]
	if !exists {
		return 0, false
	}
	switch v := raw.(type) {
	case float64:
		if float64(int(v)) != v {
			return 0, false
		}
		return int(v), true
	case int:
		return v, true
	}
	return 0, false
}

func argFloat(m map[string]any, key string, fallback float64) float64 {
	if v, ok := argFloatRequired(m, key); ok {
		return v
	}
	return fallback
}

func argFloatRequired(m map[string]any, key string) (float64, bool) {
	raw, exists := m[key]
	if !exists {
		return 0, false
	}
	switch v := raw.(type) {
	case float64:
		return v, true
	case int:
		return float64(v), true
	}
	return 0, false
}

func argStringRequired(m map[string]any, key string) (string, bool) {
	s, ok := m[key].(string)
	return s, ok && s != ""
}
