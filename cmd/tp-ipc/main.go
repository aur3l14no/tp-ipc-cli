package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aur3l14no/tp-ipc-cli/internal/config"
	"github.com/aur3l14no/tp-ipc-cli/internal/ipc"
	"github.com/aur3l14no/tp-ipc-cli/internal/live"
)

var version = "0.3.3"

type globalOptions struct {
	jsonOut bool
	ov      config.Overrides
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func extractGlobalFlags(args []string, stdin io.Reader) (globalOptions, []string, error) {
	opts := globalOptions{
		ov: config.Overrides{Stdin: stdin},
	}
	rest := make([]string, 0, len(args))

	takeValue := func(i *int, flagName string, inline string, hasInline bool) (string, error) {
		if hasInline {
			return inline, nil
		}
		if *i+1 >= len(args) {
			return "", fmt.Errorf("flag %s requires a value", flagName)
		}
		*i++
		return args[*i], nil
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			rest = append(rest, args[i:]...)
			break
		}
		name := arg
		inlineVal := ""
		hasInline := false
		if eq := strings.IndexByte(arg, '='); eq > 0 && strings.HasPrefix(arg, "-") {
			name = arg[:eq]
			inlineVal = arg[eq+1:]
			hasInline = true
		}

		switch name {
		case "--json":
			if hasInline {
				b, err := strconv.ParseBool(inlineVal)
				if err != nil {
					return opts, nil, fmt.Errorf("invalid --json=%q", inlineVal)
				}
				opts.jsonOut = b
			} else {
				opts.jsonOut = true
			}
		case "--camera", "-c":
			v, err := takeValue(&i, name, inlineVal, hasInline)
			if err != nil {
				return opts, nil, err
			}
			opts.ov.Camera = v
		case "--host", "-H":
			v, err := takeValue(&i, name, inlineVal, hasInline)
			if err != nil {
				return opts, nil, err
			}
			opts.ov.Host = v
		case "--user", "-u":
			v, err := takeValue(&i, name, inlineVal, hasInline)
			if err != nil {
				return opts, nil, err
			}
			opts.ov.User = v
		case "--password-file":
			v, err := takeValue(&i, name, inlineVal, hasInline)
			if err != nil {
				return opts, nil, err
			}
			opts.ov.PasswordFile = v
		case "--password-stdin":
			opts.ov.PasswordStdin = true
		case "--http-port":
			v, err := takeValue(&i, name, inlineVal, hasInline)
			if err != nil {
				return opts, nil, err
			}
			p, err := strconv.Atoi(v)
			if err != nil || p < 1 || p > 65535 {
				return opts, nil, fmt.Errorf("invalid --http-port %q", v)
			}
			opts.ov.HTTPPort = p
		case "--rtsp-port":
			v, err := takeValue(&i, name, inlineVal, hasInline)
			if err != nil {
				return opts, nil, err
			}
			p, err := strconv.Atoi(v)
			if err != nil || p < 1 || p > 65535 {
				return opts, nil, fmt.Errorf("invalid --rtsp-port %q", v)
			}
			opts.ov.RTSPPort = p
		case "--onvif-port":
			v, err := takeValue(&i, name, inlineVal, hasInline)
			if err != nil {
				return opts, nil, err
			}
			p, err := strconv.Atoi(v)
			if err != nil || p < 1 || p > 65535 {
				return opts, nil, fmt.Errorf("invalid --onvif-port %q", v)
			}
			opts.ov.ONVIFPort = p
		case "--proxy", "-x":
			v, err := takeValue(&i, name, inlineVal, hasInline)
			if err != nil {
				return opts, nil, err
			}
			opts.ov.Proxy = v
		case "--ssh":
			v, err := takeValue(&i, name, inlineVal, hasInline)
			if err != nil {
				return opts, nil, err
			}
			opts.ov.Proxy = config.EnsureSSHProxyPrefix(v)
		default:
			rest = append(rest, arg)
		}
	}
	return opts, rest, nil
}

func run(ctx context.Context, rawArgs []string, stdin io.Reader, stdout, stderr io.Writer) error {
	defer ipc.CloseSharedProxies()

	g, args, err := extractGlobalFlags(rawArgs, stdin)
	if err != nil {
		return err
	}
	if len(args) == 0 {
		printUsage(stdout)
		return nil
	}

	cmd := args[0]
	subArgs := args[1:]

	switch cmd {
	case "help", "--help", "-h":
		printUsage(stdout)
		return nil
	case "version", "--version", "-v":
		if g.jsonOut {
			return writeJSON(stdout, map[string]any{"name": "tp-ipc", "version": version})
		}
		fmt.Fprintf(stdout, "tp-ipc %s\n", version)
		return nil
	case "discover":
		return cmdDiscover(ctx, g, subArgs, stdout)
	case "camera", "cameras", "cam":
		return cmdCamera(ctx, g, subArgs, stdin, stdout, stderr)
	case "configure":
		return cmdConfigure(ctx, g, subArgs, stdin, stdout, stderr, true)
	case "live":
		return cmdLive(ctx, g, subArgs, stdout)
	}

	cfg, err := config.Load(g.ov)
	if err != nil {
		return err
	}
	client, err := ipc.NewClient(cfg)
	if err != nil {
		return err
	}
	defer client.Close()

	switch cmd {
	case "check":
		info, err := client.DeviceInfo(ctx)
		if err != nil {
			return err
		}
		out := map[string]any{
			"ok":        true,
			"camera":    cfg.Name,
			"host":      cfg.Host,
			"model":     info.Model,
			"firmware":  info.Firmware,
			"alias":     info.Alias,
			"rtsp_main": cfg.RTSPURL("stream1", true),
			"rtsp_sub":  cfg.RTSPURL("stream2", true),
			"onvif":     cfg.ONVIFBaseURL() + "/onvif/service",
		}
		if p := cfg.RedactedProxy(); p != "" {
			out["proxy"] = p
		}
		if g.jsonOut {
			return writeJSON(stdout, out)
		}
		camLabel := cfg.Host
		if cfg.Name != "" {
			camLabel = fmt.Sprintf("%s @ %s", cfg.Name, cfg.Host)
		}
		fmt.Fprintf(stdout, "Connected: %s (%s) [%s]\nFirmware:  %s\nRTSP 4K:   %s\nRTSP Sub:  %s\n",
			info.Model, info.Alias, camLabel, info.Firmware, cfg.RTSPURL("stream1", true), cfg.RTSPURL("stream2", true))
		if p := cfg.RedactedProxy(); p != "" {
			fmt.Fprintf(stdout, "Proxy:     %s\n", p)
		}
		return nil

	case "activation":
		st, err := client.ActivationStatus(ctx)
		if err != nil {
			return err
		}
		if g.jsonOut {
			return writeJSON(stdout, st)
		}
		fmt.Fprintf(stdout, "State:       %s (code %d)\nUsername:    %s\nCredentials: %v\n",
			st.State, st.Code, st.Username, st.CredentialsConfigured)
		return nil

	case "info":
		info, err := client.DeviceInfo(ctx)
		if err != nil {
			return err
		}
		if g.jsonOut {
			return writeJSON(stdout, info)
		}
		fmt.Fprintf(stdout, "Model:      %s (%s)\nAlias:      %s\nFirmware:   %s\nMAC:        %s\nFeatures:   ptz=%v human_detection=%v tracking=%v privacy=%v\n",
			info.Model, info.Hardware, info.Alias, info.Firmware, info.MAC,
			info.Capabilities.PTZ, info.Capabilities.HumanDetection, info.Capabilities.Tracking, info.Capabilities.Privacy)
		return nil

	case "status":
		st, err := client.CameraStatus(ctx)
		if err != nil {
			return err
		}
		if g.jsonOut {
			return writeJSON(stdout, st)
		}
		fmt.Fprintf(stdout, "Privacy Mask:   %v\nNight Vision:   %s\nRotation:       %s\nTracking:       %v\nPerson Detect:  %v\nMotion Detect:  %v\nTamper Detect:  %v\nStatus LED:     %v\nSpeaker Volume: %v\n",
			st.Privacy["enabled"], st.NightVision, st.Rotation,
			st.Tracking["enabled"], st.Person["enabled"], st.Motion["enabled"], st.Tamper["enabled"],
			st.LED["enabled"], st.Speaker["volume"])
		if len(st.Storage) == 0 {
			fmt.Fprintln(stdout, "SD Storage:     none")
		} else {
			for _, d := range st.Storage {
				fmt.Fprintf(stdout, "SD Storage:     status=%s free=%s total=%s\n", d.Status, d.FreeSpace, d.TotalSpace)
			}
		}
		return nil

	case "snap", "snapshot":
		return cmdSnap(ctx, client, g, subArgs, stdout)

	case "record":
		return cmdRecord(ctx, client, g, subArgs, stdout)

	case "play-audio", "say":
		if len(subArgs) != 1 {
			return errors.New("usage: tp-ipc play-audio <audio-file>")
		}
		res, err := client.PlayAudioFile(ctx, subArgs[0])
		if err != nil {
			return err
		}
		if g.jsonOut {
			return writeJSON(stdout, res)
		}
		fmt.Fprintf(stdout, "Played %s (%d RTP packets, %d bytes)\n", subArgs[0], res.SentRTPPackets, res.SentBytes)
		return nil

	case "ptz":
		return cmdPTZ(ctx, client, g, subArgs, stdout)

	case "preset", "presets":
		return cmdPreset(ctx, client, g, subArgs, stdout)

	case "privacy":
		enabled, err := parseToggleArg(subArgs, "privacy")
		if err != nil {
			return err
		}
		res, err := client.SetPrivacy(ctx, enabled)
		if err != nil {
			return err
		}
		return writeToggleOutcome(stdout, g.jsonOut, "privacy", enabled, res)

	case "led":
		enabled, err := parseToggleArg(subArgs, "led")
		if err != nil {
			return err
		}
		res, err := client.SetLED(ctx, enabled)
		if err != nil {
			return err
		}
		return writeToggleOutcome(stdout, g.jsonOut, "led", enabled, res)

	case "tracking":
		enabled, err := parseToggleArg(subArgs, "tracking")
		if err != nil {
			return err
		}
		res, err := client.SetTracking(ctx, enabled)
		if err != nil {
			return err
		}
		return writeToggleOutcome(stdout, g.jsonOut, "tracking", enabled, res)

	case "volume":
		if len(subArgs) != 1 {
			return errors.New("usage: tp-ipc volume <0-100>")
		}
		vol, err := strconv.Atoi(subArgs[0])
		if err != nil {
			return fmt.Errorf("invalid volume %q", subArgs[0])
		}
		res, err := client.SetSpeakerVolume(ctx, vol)
		if err != nil {
			return err
		}
		if g.jsonOut {
			return writeJSON(stdout, map[string]any{"volume": vol, "response": res})
		}
		fmt.Fprintf(stdout, "Speaker volume set to %d\n", vol)
		return nil

	case "detect":
		if len(subArgs) != 2 {
			return errors.New("usage: tp-ipc detect <person|motion|tamper> <on|off>")
		}
		enabled, err := parseBoolToken(subArgs[1])
		if err != nil {
			return err
		}
		res, err := client.SetDetection(ctx, subArgs[0], enabled)
		if err != nil {
			return err
		}
		return writeToggleOutcome(stdout, g.jsonOut, "detect:"+subArgs[0], enabled, res)

	case "night-vision":
		if len(subArgs) != 1 {
			return errors.New("usage: tp-ipc night-vision <ir|color|smart>")
		}
		canonical, err := ipc.NormalizeNightVisionMode(subArgs[0])
		if err != nil {
			return err
		}
		res, err := client.SetNightVision(ctx, canonical)
		if err != nil {
			return err
		}
		if g.jsonOut {
			return writeJSON(stdout, map[string]any{"night_vision": canonical, "response": res})
		}
		fmt.Fprintf(stdout, "Night vision set to %s\n", canonical)
		return nil

	case "alarm":
		return cmdAlarm(ctx, client, g, subArgs, stdout)

	case "events":
		fs := flag.NewFlagSet("events", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		waitSec := fs.Int("wait", 5, "Wait duration in seconds (1-15)")
		if err := fs.Parse(subArgs); err != nil {
			return errors.New("usage: tp-ipc events [--wait 1..15]")
		}
		ev, err := client.PollEvents(ctx, *waitSec)
		if err != nil {
			return err
		}
		if g.jsonOut {
			return writeJSON(stdout, ev)
		}
		if len(ev) == 0 {
			fmt.Fprintf(stdout, "No ONVIF events observed in %ds\n", *waitSec)
			return nil
		}
		for _, e := range ev {
			fmt.Fprintf(stdout, "[%s] %s %v\n", e.UTCTime, e.Topic, e.Data)
		}
		return nil

	case "watch-person":
		fs := flag.NewFlagSet("watch-person", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		waitSec := fs.Int("wait", 10, "Wait duration in seconds (1-30)")
		if err := fs.Parse(subArgs); err != nil {
			return errors.New("usage: tp-ipc watch-person [--wait 1..30]")
		}
		res, err := client.WaitPersonAlarm(ctx, *waitSec)
		if err != nil {
			return err
		}
		if g.jsonOut {
			return writeJSON(stdout, res)
		}
		if res.Detected {
			fmt.Fprintf(stdout, "Person detected at %s (signal=%s)\n", time.Unix(res.ObservedAtUnix, 0).Format(time.RFC3339), res.Signal)
		} else {
			fmt.Fprintf(stdout, "No person alarm triggered within %ds\n", *waitSec)
		}
		return nil

	case "recordings", "sd":
		return cmdRecordings(ctx, client, g, subArgs, stdout)

	case "export":
		return cmdDownloadRecording(ctx, client, g, subArgs, stdout)

	case "raw":
		if len(subArgs) != 1 {
			return errors.New(`usage: tp-ipc raw '{"method":"get","device_info":{"name":["basic_info"]}}'`)
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(subArgs[0]), &payload); err != nil {
			return fmt.Errorf("invalid raw JSON payload: %w", err)
		}
		res, err := client.DoDS(ctx, payload)
		if err != nil {
			return err
		}
		return writeJSON(stdout, res)

	default:
		return fmt.Errorf("unknown command %q (run `tp-ipc --help` for usage)", cmd)
	}
}

func cmdDiscover(ctx context.Context, g globalOptions, subArgs []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("discover", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	timeoutSec := fs.Int("timeout", 2, "Discovery timeout in seconds (1-15)")
	cidr := fs.String("cidr", "", "Optional IPv4 CIDR to scan across routed VLANs (e.g. 192.168.1.0/24)")
	if err := fs.Parse(subArgs); err != nil || *timeoutSec < 1 || *timeoutSec > 15 {
		return errors.New("usage: tp-ipc discover [--timeout 2] [--cidr 192.168.1.0/24]")
	}
	proxySpec := strings.TrimSpace(g.ov.Proxy)
	if proxySpec == "" {
		if v := strings.TrimSpace(os.Getenv("IPC_PROXY")); v != "" {
			proxySpec = v
		} else if v := strings.TrimSpace(os.Getenv("IPC_SSH")); v != "" {
			proxySpec = config.EnsureSSHProxyPrefix(v)
		}
	}

	var (
		found []ipc.DiscoveredCamera
		err   error
	)
	if strings.TrimSpace(*cidr) != "" {
		found, err = ipc.DiscoverCIDRWithProxy(ctx, *cidr, proxySpec, time.Duration(*timeoutSec)*time.Second)
	} else {
		if proxySpec != "" {
			p, pErr := config.ParseProxyInput(proxySpec)
			if pErr != nil {
				return pErr
			}
			if !p.DirectOverride && p.Kind != "" {
				return fmt.Errorf("L2 multicast discovery cannot traverse proxy %s; pass --cidr <subnet/24> (e.g. --cidr 192.168.1.0/24)", p.Redacted())
			}
		}
		found, err = ipc.DiscoverLAN(ctx, time.Duration(*timeoutSec)*time.Second)
	}
	if err != nil {
		return err
	}
	if g.jsonOut {
		return writeJSON(stdout, map[string]any{"count": len(found), "devices": found})
	}
	if len(found) == 0 {
		if *cidr != "" {
			fmt.Fprintf(stdout, "No TP-LINK IPC cameras found in %s\n", *cidr)
		} else {
			fmt.Fprintln(stdout, "No ONVIF cameras responded via L2 multicast (for cross-VLAN subnets, pass --cidr e.g. 192.168.1.0/24)")
		}
		return nil
	}
	for _, d := range found {
		tag := "ONVIF"
		if d.IsTPLinkIPC {
			tag = fmt.Sprintf("TP-LINK IPC (%s)", d.ActivationState)
		}
		model := d.Model
		if model == "" {
			model = "-"
		}
		fmt.Fprintf(stdout, "%-16s  %-26s  model=%-18s  %s\n", d.Host, tag, model, d.ONVIFEndpoint)
	}
	return nil
}

func cmdCamera(ctx context.Context, g globalOptions, subArgs []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(subArgs) == 0 {
		subArgs = []string{"list"}
	}
	switch subArgs[0] {
	case "list", "ls":
		st, err := config.LoadStore()
		if err != nil {
			return err
		}
		cams := st.Summaries()
		if g.jsonOut {
			return writeJSON(stdout, map[string]any{
				"default_camera": st.DefaultCamera,
				"count":          len(cams),
				"cameras":        cams,
			})
		}
		if len(cams) == 0 {
			fmt.Fprintln(stdout, "No cameras configured (use `tp-ipc camera add <name> --host <ip>` or `tp-ipc discover`)")
			return nil
		}
		for _, c := range cams {
			marker := " "
			if c.Default {
				marker = "*"
			}
			extra := ""
			if c.Proxy != "" {
				extra = " via " + c.Proxy
			}
			fmt.Fprintf(stdout, "%s %-14s  %s@%s  (http:%d rtsp:%d onvif:%d%s)\n",
				marker, c.Name, c.User, c.Host, c.HTTPPort, c.RTSPPort, c.ONVIFPort, extra)
		}
		return nil

	case "add", "set":
		fs := flag.NewFlagSet("camera-add", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		makeDefault := fs.Bool("default", false, "Set as default camera")
		if err := fs.Parse(subArgs[1:]); err != nil || fs.NArg() != 1 {
			return errors.New("usage: tp-ipc camera add <name> [--default] --host <ip> [--user admin] [--password-stdin]")
		}
		g.ov.Camera = fs.Arg(0)
		return cmdConfigure(ctx, g, nil, stdin, stdout, stderr, *makeDefault)

	case "use", "default":
		if len(subArgs) != 2 {
			return errors.New("usage: tp-ipc camera use <name>")
		}
		name := strings.TrimSpace(subArgs[1])
		st, err := config.LoadStore()
		if err != nil {
			return err
		}
		if _, ok := st.Cameras[name]; !ok {
			return fmt.Errorf("camera %q not found", name)
		}
		st.DefaultCamera = name
		path, err := config.SaveStore(st)
		if err != nil {
			return err
		}
		if g.jsonOut {
			return writeJSON(stdout, map[string]any{"default_camera": name, "path": path})
		}
		fmt.Fprintf(stdout, "Default camera set to %q\n", name)
		return nil

	case "remove", "rm", "delete":
		if len(subArgs) != 2 {
			return errors.New("usage: tp-ipc camera remove <name>")
		}
		name := strings.TrimSpace(subArgs[1])
		st, err := config.LoadStore()
		if err != nil {
			return err
		}
		if _, ok := st.Cameras[name]; !ok {
			return fmt.Errorf("camera %q not found", name)
		}
		delete(st.Cameras, name)
		if st.DefaultCamera == name {
			st.DefaultCamera = ""
			for k := range st.Cameras {
				st.DefaultCamera = k
				break
			}
		}
		path, err := config.SaveStore(st)
		if err != nil {
			return err
		}
		if g.jsonOut {
			return writeJSON(stdout, map[string]any{"removed": name, "default_camera": st.DefaultCamera, "path": path})
		}
		fmt.Fprintf(stdout, "Removed camera %q\n", name)
		return nil

	default:
		return errors.New("usage: tp-ipc camera <list|add|use|remove>")
	}
}

func cmdConfigure(ctx context.Context, g globalOptions, subArgs []string, stdin io.Reader, stdout, stderr io.Writer, makeDefault bool) error {
	if len(subArgs) > 0 {
		return errors.New("usage: tp-ipc configure [-c <name>] [--host IP] [--user admin] [--password-stdin|--password-file PATH]")
	}

	profileName := strings.TrimSpace(g.ov.Camera)
	cfg, err := config.LoadForConfigure(g.ov)
	if err != nil {
		return err
	}

	reader := bufio.NewReader(stdin)
	if cfg.Host == "" {
		fmt.Fprint(stderr, "Camera IP or URL: ")
		line, err := reader.ReadString('\n')
		if err != nil && len(strings.TrimSpace(line)) == 0 {
			return errors.New("camera host is required")
		}
		scheme, host, port, err := config.ParseHostInput(line)
		if err != nil {
			return err
		}
		cfg.Scheme = scheme
		cfg.Host = host
		if port > 0 {
			cfg.HTTPPort = port
		} else if scheme == "https" && cfg.HTTPPort == config.DefaultHTTPPort {
			cfg.HTTPPort = 443
		}
	}
	if cfg.Password == "" {
		if strings.TrimSpace(g.ov.User) == "" {
			fmt.Fprintf(stderr, "Camera username [%s]: ", cfg.User)
			uLine, _ := reader.ReadString('\n')
			if u := strings.TrimSpace(uLine); u != "" {
				cfg.User = u
			}
		}
		fmt.Fprint(stderr, "Camera password: ")
		pw, err := readInteractivePassword(ctx, stdin, reader, stderr)
		if err != nil {
			return err
		}
		cfg.Password = pw
	}

	probeClient, err := ipc.NewClient(config.Settings{
		Scheme:   cfg.Scheme,
		Host:     cfg.Host,
		HTTPPort: cfg.HTTPPort,
		Proxy:    cfg.Proxy,
	})
	if err != nil {
		return err
	}
	act, err := probeClient.ActivationStatus(ctx)
	if err != nil {
		return err
	}
	if act.State != "activated" {
		return fmt.Errorf("camera state is %q; finish initial setup in the TP-LINK app or camera web UI first", act.State)
	}

	authClient, err := ipc.NewClient(cfg)
	if err != nil {
		return err
	}
	info, err := authClient.DeviceInfo(ctx)
	if err != nil {
		return err
	}
	if profileName == "" {
		if info.Alias != "" {
			profileName = info.Alias
		} else {
			profileName = "default"
		}
	}
	cfg.Name = profileName

	savedPath, err := config.Save(cfg, makeDefault)
	if err != nil {
		return err
	}
	if g.jsonOut {
		return writeJSON(stdout, map[string]any{
			"saved":  true,
			"camera": profileName,
			"path":   savedPath,
			"model":  info.Model,
		})
	}
	fmt.Fprintf(stdout, "Verified %s (%s) as profile %q. Saved to %s (0600)\n", info.Model, info.Firmware, profileName, savedPath)
	return nil
}

func readInteractivePassword(ctx context.Context, stdin io.Reader, reader *bufio.Reader, stderr io.Writer) (string, error) {
	var (
		restore = func() {}
		hidden  bool
	)
	if reader.Buffered() == 0 {
		restore, hidden = disableTerminalEcho(stdin)
	}
	defer restore()

	type readResult struct {
		line string
		err  error
	}
	ch := make(chan readResult, 1)
	go func() {
		line, err := reader.ReadString('\n')
		ch <- readResult{line: line, err: err}
	}()

	var (
		pLine string
		err   error
	)
	select {
	case <-ctx.Done():
		restore()
		if hidden {
			fmt.Fprintln(stderr)
		}
		return "", ctx.Err()
	case res := <-ch:
		restore()
		if hidden {
			fmt.Fprintln(stderr)
		}
		pLine, err = res.line, res.err
	}

	pw := strings.TrimRight(pLine, "\r\n")
	if pw == "" {
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		return "", errors.New("camera password is required")
	}
	return pw, nil
}

func cmdSnap(ctx context.Context, client *ipc.Client, g globalOptions, subArgs []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("snap", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	outPath := fs.String("o", "", "Output JPEG path ('-' for stdout)")
	hq := fs.Bool("hq", false, "Use 4K main stream (/stream1)")
	hqAlias := fs.Bool("4k", false, "Alias for --hq")
	zoom := fs.Int("zoom", 1, "Digital crop factor (1-5)")
	focusX := fs.Float64("focus-x", 0.5, "Crop horizontal focus [0,1]")
	focusY := fs.Float64("focus-y", 0.5, "Crop vertical focus [0,1]")
	if err := fs.Parse(subArgs); err != nil {
		return errors.New("usage: tp-ipc snap [-o out.jpg] [--hq|--4k] [--zoom 1..5] [--focus-x 0.5] [--focus-y 0.5]")
	}
	if fs.NArg() > 1 {
		return errors.New("too many arguments for snap")
	}
	target := *outPath
	if target == "" && fs.NArg() == 1 {
		target = fs.Arg(0)
	}

	jpegBytes, err := client.Snapshot(ctx, ipc.SnapshotOptions{
		HighQuality: *hq || *hqAlias,
		Zoom:        *zoom,
		FocusX:      *focusX,
		FocusY:      *focusY,
	})
	if err != nil {
		return err
	}

	if target == "-" {
		_, err := stdout.Write(jpegBytes)
		return err
	}
	if target == "" {
		prefix := "snap"
		if n := client.Settings().Name; n != "" && n != "default" {
			prefix = "snap-" + n
		}
		target = fmt.Sprintf("%s-%s.jpg", prefix, time.Now().Format("20060102-150405"))
	}
	if err := os.WriteFile(target, jpegBytes, 0o644); err != nil {
		return fmt.Errorf("write snapshot %s: %w", target, err)
	}
	if g.jsonOut {
		return writeJSON(stdout, map[string]any{
			"camera":       client.Settings().Name,
			"path":         target,
			"bytes":        len(jpegBytes),
			"high_quality": *hq || *hqAlias || *zoom > 1,
			"zoom":         *zoom,
		})
	}
	fmt.Fprintf(stdout, "Saved snapshot to %s (%d bytes)\n", target, len(jpegBytes))
	return nil
}

func cmdRecord(ctx context.Context, client *ipc.Client, g globalOptions, subArgs []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("record", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	seconds := fs.Int("d", 5, "Duration in seconds (1-300)")
	secLong := fs.Int("seconds", 0, "Duration in seconds (1-300)")
	outPath := fs.String("o", "", "Output file (.mkv or .mp4)")
	hq := fs.Bool("hq", false, "Record 4K main stream (/stream1)")
	hqAlias := fs.Bool("4k", false, "Alias for --hq")
	if err := fs.Parse(subArgs); err != nil {
		return errors.New("usage: tp-ipc record [-d 5] [--hq|--4k] [-o clip.mkv]")
	}
	dur := *seconds
	if *secLong > 0 {
		dur = *secLong
	}
	target := *outPath
	if target == "" && fs.NArg() == 1 {
		target = fs.Arg(0)
	}
	if target == "" && client.Settings().MediaDir == "" {
		prefix := "clip"
		if n := client.Settings().Name; n != "" && n != "default" {
			prefix = "clip-" + n
		}
		target = fmt.Sprintf("%s-%s.mkv", prefix, time.Now().Format("20060102-150405"))
	}
	res, err := client.RecordClip(ctx, dur, *hq || *hqAlias, target, "")
	if err != nil {
		return err
	}
	if g.jsonOut {
		return writeJSON(stdout, res)
	}
	fmt.Fprintf(stdout, "Recorded %ds (%s) to %s (%d bytes)\n", res.Seconds, res.Quality, res.Path, res.Bytes)
	return nil
}

func cmdLive(ctx context.Context, g globalOptions, subArgs []string, stdout io.Writer) error {
	normalized := make([]string, 0, len(subArgs))
	for i := 0; i < len(subArgs); i++ {
		arg := subArgs[i]
		if arg == "--" {
			normalized = append(normalized, subArgs[i:]...)
			break
		}
		if arg == "--player" || arg == "-player" {
			if i+1 >= len(subArgs) || strings.HasPrefix(subArgs[i+1], "-") {
				normalized = append(normalized, "--player=auto")
				continue
			}
		}
		normalized = append(normalized, arg)
	}

	fs := flag.NewFlagSet("live", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	hq := fs.Bool("hq", false, "Start on 4K main stream (/stream1)")
	hqAlias := fs.Bool("4k", false, "Alias for --hq")
	listenAddr := fs.String("listen", "", "Listen address for web console (default 127.0.0.1:0)")
	port := fs.Int("port", 0, "Listen port on 127.0.0.1 (shorthand for --listen 127.0.0.1:<port>)")
	noOpen := fs.Bool("no-open", false, "Do not auto-open browser")
	player := fs.String("player", "", "Open in native player instead of web console (auto, mpv, ffplay, iina, vlc)")
	if err := fs.Parse(normalized); err != nil || fs.NArg() > 0 {
		return errors.New("usage: tp-ipc live [--hq|--4k] [--listen 127.0.0.1:0] [--port PORT] [--no-open] [--player [auto|mpv|ffplay|iina|vlc]]")
	}

	highQuality := *hq || *hqAlias

	if strings.TrimSpace(*player) != "" {
		cfg, err := config.Load(g.ov)
		if err != nil {
			return err
		}
		client, err := ipc.NewClient(cfg)
		if err != nil {
			return err
		}
		defer client.Close()
		var progressOut io.Writer = stdout
		if g.jsonOut {
			progressOut = nil
		}
		if err := live.LaunchPlayer(ctx, client, highQuality, *player, progressOut); err != nil {
			return err
		}
		if g.jsonOut {
			return writeJSON(stdout, map[string]any{"ok": true, "mode": "player", "camera": cfg.Name})
		}
		return nil
	}

	bind := strings.TrimSpace(*listenAddr)
	if bind == "" {
		if *port < 0 || *port > 65535 {
			return fmt.Errorf("invalid --port %d", *port)
		}
		bind = fmt.Sprintf("127.0.0.1:%d", *port)
	}

	srv, err := live.NewServer(live.Options{
		ListenAddr:  bind,
		HighQuality: highQuality,
		Overrides:   g.ov,
	})
	if err != nil {
		return err
	}

	baseURL, authURL, waitFn, err := srv.Start(ctx)
	if err != nil {
		return err
	}

	if g.jsonOut {
		_ = writeJSON(stdout, map[string]any{
			"mode":     "web",
			"camera":   srv.DefaultCamera(),
			"base_url": baseURL,
			"url":      authURL,
		})
	} else {
		fmt.Fprintf(stdout, "Live web console (%s): %s\nPress Ctrl+C to stop.\n", srv.DefaultCamera(), authURL)
	}

	if !*noOpen {
		_ = live.OpenBrowser(authURL)
	}

	return waitFn()
}

func cmdPTZ(ctx context.Context, client *ipc.Client, g globalOptions, subArgs []string, stdout io.Writer) error {
	if len(subArgs) == 0 {
		subArgs = []string{"status"}
	}
	action := subArgs[0]
	rest := subArgs[1:]

	switch action {
	case "status":
		pos, err := client.PTZStatus(ctx)
		if err != nil {
			return err
		}
		if g.jsonOut {
			return writeJSON(stdout, pos)
		}
		fmt.Fprintf(stdout, "Pan: %.4f  Tilt: %.4f  (source: %s)\n", pos.Pan, pos.Tilt, pos.Source)
		return nil

	case "stop":
		if err := client.PTZStop(ctx); err != nil {
			return err
		}
		if g.jsonOut {
			return writeJSON(stdout, map[string]any{"stopped": true})
		}
		fmt.Fprintln(stdout, "PTZ stopped")
		return nil

	case "left", "right", "up", "down":
		fs := flag.NewFlagSet("ptz-dir", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		step := fs.Float64("step", 0.05, "Relative step size (0.01..0.25)")
		if err := fs.Parse(rest); err != nil || *step <= 0 || *step > 0.25 {
			return errors.New("usage: tp-ipc ptz <left|right|up|down> [--step 0.05]")
		}
		var pan, tilt float64
		switch action {
		case "left":
			pan = -*step
		case "right":
			pan = *step
		case "up":
			tilt = *step
		case "down":
			tilt = -*step
		}
		if err := client.PTZMoveRelative(ctx, pan, tilt); err != nil {
			return err
		}
		if g.jsonOut {
			return writeJSON(stdout, map[string]any{"moved": true, "direction": action, "pan": pan, "tilt": tilt})
		}
		fmt.Fprintf(stdout, "Moved %s (pan=%+.3f, tilt=%+.3f)\n", action, pan, tilt)
		return nil

	case "move":
		pan, tilt, err := parsePanTiltArgs("move", rest)
		if err != nil {
			return err
		}
		if err := client.PTZMoveRelative(ctx, pan, tilt); err != nil {
			return err
		}
		if g.jsonOut {
			return writeJSON(stdout, map[string]any{"moved": true, "mode": "relative", "pan": pan, "tilt": tilt})
		}
		fmt.Fprintf(stdout, "Moved relative (pan=%+.4f, tilt=%+.4f)\n", pan, tilt)
		return nil

	case "goto":
		pan, tilt, err := parsePanTiltArgs("goto", rest)
		if err != nil {
			return err
		}
		if err := client.PTZMoveAbsolute(ctx, pan, tilt); err != nil {
			return err
		}
		if g.jsonOut {
			return writeJSON(stdout, map[string]any{"moved": true, "mode": "absolute", "pan": pan, "tilt": tilt})
		}
		fmt.Fprintf(stdout, "Moved to absolute position (pan=%.4f, tilt=%.4f)\n", pan, tilt)
		return nil

	default:
		return errors.New("usage: tp-ipc ptz <status|move|goto|left|right|up|down|stop>")
	}
}

func parsePanTiltArgs(mode string, args []string) (float64, float64, error) {
	if len(args) == 2 && !strings.HasPrefix(args[0], "--") && !strings.HasPrefix(args[1], "--") {
		p, errP := strconv.ParseFloat(args[0], 64)
		t, errT := strconv.ParseFloat(args[1], 64)
		if errP == nil && errT == nil {
			return p, t, nil
		}
	}
	fs := flag.NewFlagSet("ptz-"+mode, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	pan := fs.Float64("pan", 0, "Pan value")
	tilt := fs.Float64("tilt", 0, "Tilt value")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return 0, 0, fmt.Errorf("usage: tp-ipc ptz %s --pan <val> --tilt <val>", mode)
	}
	return *pan, *tilt, nil
}

func cmdPreset(ctx context.Context, client *ipc.Client, g globalOptions, subArgs []string, stdout io.Writer) error {
	if len(subArgs) == 0 {
		subArgs = []string{"list"}
	}
	switch subArgs[0] {
	case "list", "ls":
		presets, raw, err := client.ListPresets(ctx)
		if err != nil {
			return err
		}
		if g.jsonOut {
			return writeJSON(stdout, map[string]any{"presets": presets, "raw": raw})
		}
		if len(presets) == 0 {
			fmt.Fprintln(stdout, "No saved presets")
			return nil
		}
		for _, p := range presets {
			coords := ""
			if p.Pan != nil && p.Tilt != nil {
				coords = fmt.Sprintf(" (pan=%.3f, tilt=%.3f)", *p.Pan, *p.Tilt)
			}
			fmt.Fprintf(stdout, "[%s] %s%s\n", p.ID, p.Name, coords)
		}
		return nil

	case "save", "add":
		if len(subArgs) != 2 {
			return errors.New("usage: tp-ipc preset save <name>")
		}
		res, err := client.SavePreset(ctx, subArgs[1])
		if err != nil {
			return err
		}
		if g.jsonOut {
			return writeJSON(stdout, res)
		}
		fmt.Fprintf(stdout, "Saved preset %q\n", subArgs[1])
		return nil

	case "goto":
		if len(subArgs) != 2 {
			return errors.New("usage: tp-ipc preset goto <id>")
		}
		res, err := client.GotoPreset(ctx, subArgs[1])
		if err != nil {
			return err
		}
		if g.jsonOut {
			return writeJSON(stdout, res)
		}
		fmt.Fprintf(stdout, "Moving to preset %s\n", subArgs[1])
		return nil

	case "remove", "rm", "delete":
		if len(subArgs) != 2 {
			return errors.New("usage: tp-ipc preset remove <id>")
		}
		if err := client.RemovePreset(ctx, subArgs[1]); err != nil {
			return err
		}
		if g.jsonOut {
			return writeJSON(stdout, map[string]any{"removed": true, "id": subArgs[1]})
		}
		fmt.Fprintf(stdout, "Removed preset %s\n", subArgs[1])
		return nil

	default:
		return errors.New("usage: tp-ipc preset <list|save|goto|remove>")
	}
}

func cmdAlarm(ctx context.Context, client *ipc.Client, g globalOptions, subArgs []string, stdout io.Writer) error {
	if len(subArgs) == 0 {
		return errors.New("usage: tp-ipc alarm <start [1-5] | stop>")
	}
	if subArgs[0] == "stop" {
		if err := client.StopAlarm(ctx); err != nil {
			return err
		}
		if g.jsonOut {
			return writeJSON(stdout, map[string]any{"stopped": true})
		}
		fmt.Fprintln(stdout, "Manual alarm stopped")
		return nil
	}
	secStr := subArgs[0]
	if subArgs[0] == "start" {
		secStr = "2"
		if len(subArgs) >= 2 {
			secStr = subArgs[1]
		}
	}
	sec, err := strconv.Atoi(secStr)
	if err != nil {
		return errors.New("usage: tp-ipc alarm <start [1-5] | stop>")
	}
	if err := client.TriggerAlarm(ctx, sec); err != nil {
		return err
	}
	if g.jsonOut {
		return writeJSON(stdout, map[string]any{"triggered": true, "seconds": sec, "stopped": true})
	}
	fmt.Fprintf(stdout, "Triggered alarm for %ds and stopped\n", sec)
	return nil
}

func cmdRecordings(ctx context.Context, client *ipc.Client, g globalOptions, subArgs []string, stdout io.Writer) error {
	if len(subArgs) == 0 {
		subArgs = []string{"dates"}
	}
	switch subArgs[0] {
	case "dates":
		month := ""
		if len(subArgs) >= 2 {
			month = subArgs[1]
		}
		dates, err := client.RecordingDates(ctx, month)
		if err != nil {
			return err
		}
		if g.jsonOut {
			return writeJSON(stdout, map[string]any{"dates": dates, "count": len(dates)})
		}
		if len(dates) == 0 {
			fmt.Fprintln(stdout, "No SD card recordings found for that month")
			return nil
		}
		for _, d := range dates {
			fmt.Fprintln(stdout, d)
		}
		return nil

	case "list", "ls":
		date := ""
		if len(subArgs) >= 2 {
			date = subArgs[1]
		}
		segs, err := client.ListRecordings(ctx, date)
		if err != nil {
			return err
		}
		if g.jsonOut {
			return writeJSON(stdout, map[string]any{"segments": segs, "count": len(segs)})
		}
		if len(segs) == 0 {
			fmt.Fprintln(stdout, "No recording segments found for that date")
			return nil
		}
		for _, s := range segs {
			fmt.Fprintf(stdout, "%s -> %s  (%4ds, %s)\n", s.StartTime, s.EndTime, s.DurationSec, s.TypeLabel)
		}
		return nil

	case "download", "export", "fetch":
		return cmdDownloadRecording(ctx, client, g, subArgs[1:], stdout)

	default:
		return errors.New("usage: tp-ipc recordings <dates [YYYY-MM] | list [YYYY-MM-DD] | download --from HH:MM --to HH:MM [-o out.mp4]>")
	}
}

func cmdDownloadRecording(ctx context.Context, client *ipc.Client, g globalOptions, subArgs []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("recordings-download", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dateStr := fs.String("date", "", "Base date YYYY-MM-DD when using HH:MM times (defaults to today)")
	fromStr := fs.String("from", "", "Start time (e.g. 12:00, 12:00:00, '2026-01-15 12:00:00', or RFC3339)")
	startAlias := fs.String("start", "", "Alias for --from")
	toStr := fs.String("to", "", "End time (e.g. 12:10, 12:10:00, '2026-01-15 12:10:00', or RFC3339)")
	endAlias := fs.String("end", "", "Alias for --to")
	outPath := fs.String("o", "", "Output file (.mp4 or .mkv)")
	if err := fs.Parse(subArgs); err != nil {
		return errors.New("usage: tp-ipc recordings download --from <start> --to <end> [--date YYYY-MM-DD] [-o out.mp4]")
	}

	startVal := strings.TrimSpace(*fromStr)
	if startVal == "" {
		startVal = strings.TrimSpace(*startAlias)
	}
	endVal := strings.TrimSpace(*toStr)
	if endVal == "" {
		endVal = strings.TrimSpace(*endAlias)
	}
	// Also support positional `<from> <to>` e.g. `tp-ipc export 12:00 12:10 -o clip.mp4`
	if startVal == "" && endVal == "" && fs.NArg() >= 2 {
		startVal = fs.Arg(0)
		endVal = fs.Arg(1)
	}
	if startVal == "" || endVal == "" {
		return errors.New("usage: tp-ipc recordings download --from <HH:MM|datetime> --to <HH:MM|datetime> [--date YYYY-MM-DD] [-o out.mp4]")
	}

	target := strings.TrimSpace(*outPath)
	if target == "" && client.Settings().MediaDir == "" {
		startUnix, endUnix, err := ipc.ParseTimeWindow(*dateStr, startVal, endVal, time.Local)
		if err != nil {
			return err
		}
		prefix := "sd"
		if safeName := config.SanitizeProfileToken(client.Settings().Name); safeName != "" && safeName != "default" {
			prefix = "sd-" + safeName
		}
		target = fmt.Sprintf("%s-%s-%s.mp4",
			prefix,
			time.Unix(startUnix, 0).In(time.Local).Format("20060102-150405"),
			time.Unix(endUnix, 0).In(time.Local).Format("150405"),
		)
	}

	res, err := client.DownloadRecording(ctx, ipc.ExportRecordingOptions{
		Date:       *dateStr,
		Start:      startVal,
		End:        endVal,
		OutputPath: target,
	})
	if err != nil {
		return err
	}
	if g.jsonOut {
		return writeJSON(stdout, res)
	}
	fmt.Fprintf(stdout, "Exported SD recording (%d segment(s), %.1fs media, %ds gap) to %s (%d bytes)\n",
		res.Segments, res.MediaDuration, res.GapDuration, res.Path, res.Bytes)
	return nil
}

func parseToggleArg(args []string, name string) (bool, error) {
	if len(args) != 1 {
		return false, fmt.Errorf("usage: tp-ipc %s <on|off>", name)
	}
	return parseBoolToken(args[0])
}

func parseBoolToken(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "on", "true", "1", "enable", "enabled":
		return true, nil
	case "off", "false", "0", "disable", "disabled":
		return false, nil
	default:
		return false, fmt.Errorf("expected on/off (got %q)", s)
	}
}

func writeToggleOutcome(w io.Writer, asJSON bool, target string, enabled bool, resp map[string]any) error {
	state := "off"
	if enabled {
		state = "on"
	}
	if asJSON {
		return writeJSON(w, map[string]any{"target": target, "state": state, "response": resp})
	}
	fmt.Fprintf(w, "%s -> %s\n", target, state)
	return nil
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `tp-ipc — Pure-Go multi-camera CLI for mainland TP-LINK TL-IPC cameras

Usage:
  tp-ipc [global flags] <command> [args]

Multi-Device & Discovery:
  discover [--cidr 192.168.1.0/24] Auto-discover ONVIF / TP-LINK cameras on LAN or VLAN
  camera list                      List configured camera profiles (* = default)
  camera add <name> [--default]    Verify login and save a named camera profile (0600)
  camera use <name>                Switch default camera profile
  camera remove <name>             Remove a saved camera profile
  configure [-c <name>]            Verify login and save camera (defaults name to device alias)

Camera Commands (target any profile via -c <name>):
  check                            Verify camera connectivity and stream URLs
  activation                       Check activation status without logging in
  info                             Show model, firmware, MAC, and capabilities
  status                           Show detectors, privacy, night vision, LED, speaker, SD card
  live [--4k] [--player [mpv|ffplay]] [--listen 127.0.0.1:0] [--no-open]
                                   Open live web console (with PTZ/controls) or local RTSP player
  snap [-o out.jpg] [--hq] [--zoom 1..5]
                                   Capture a JPEG frame over RTSP
  record [-d 5] [--hq] [-o clip.mkv]
                                   Record live RTSP clip (.mkv lossless or .mp4)
  export --from 12:00 --to 12:10 [--date YYYY-MM-DD] [-o out.mp4]
                                   Download historical SD card video across time window
  play-audio <file>                Stream local audio through camera speaker (MULTITRANS)
  ptz <status|move|goto|left|right|up|down|stop>
                                   Inspect or move pan/tilt gimbal
  preset <list|save|goto|remove>   Manage saved PTZ presets
  privacy <on|off>                 Toggle physical lens privacy mask
  led <on|off>                     Toggle status LED
  volume <0-100>                   Set camera speaker volume
  tracking <on|off>                Toggle on-device target tracking
  detect <person|motion|tamper> <on|off>
                                   Toggle on-device detection modules
  night-vision <ir|color|smart>    Set night vision mode
  alarm <start [1-5] | stop>       Trigger or stop manual alarm
  events [--wait 5]                Poll ONVIF PullPoint motion/tamper events
  watch-person [--wait 10]         Wait silently for person white-light linkage signal
  recordings <dates [YYYY-MM] | list [YYYY-MM-DD] | download --from ... --to ...>
                                   Query or download SD card recordings
  raw '<json>'                     Execute a raw /stok=.../ds JSON request

Global Flags:
  -c, --camera <name>              Select named camera profile
  -H, --host <ip-or-url>           Camera IP, host:port, or http(s)://host:port
  -u, --user <username>            Camera username (default: admin)
      --password-file <path>       Read camera password from file
      --password-stdin             Read camera password from stdin
  -x, --proxy <spec>               Tunnel via SSH host, ssh://, socks5://, http://, or direct
      --ssh <user@host[:port]>     Shorthand for --proxy ssh://<user@host[:port]>
      --http-port <port>           Override HTTP control port (default: 80)
      --rtsp-port <port>           Override RTSP/MULTITRANS port (default: 554)
      --onvif-port <port>          Override ONVIF port (default: 2020)
      --json                       Emit machine-readable JSON output

Environment Variables:
  Single camera:  IPC_CAMERA, IPC_HOST, IPC_USER, IPC_PASSWORD, IPC_PASSWORD_FILE, IPC_PROXY, IPC_SSH
  Multi-camera:   IPC_CAMERAS (JSON map) and/or IPC_HOST_<NAME>, IPC_USER_<NAME>, IPC_PASSWORD_<NAME>, IPC_PROXY_<NAME>
  Media dir:      IPC_MEDIA_DIR
`)
}
