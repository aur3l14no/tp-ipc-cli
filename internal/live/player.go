package live

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/aur3l14no/tp-ipc-cli/internal/ipc"
)

type playerCandidate struct {
	kind string
	bins []string
}

var defaultPlayers = []playerCandidate{
	{kind: "mpv", bins: []string{"mpv"}},
	{kind: "ffplay", bins: []string{"ffplay"}},
	{kind: "iina", bins: []string{"iina", "/Applications/IINA.app/Contents/MacOS/iina-cli"}},
	{kind: "vlc", bins: []string{"vlc", "/Applications/VLC.app/Contents/MacOS/VLC"}},
}

// ResolvePlayer finds a local media player executable matching spec ("auto", "mpv", "ffplay", "iina", "vlc", or binary name).
func ResolvePlayer(spec string) (kind string, binPath string, err error) {
	req := strings.ToLower(strings.TrimSpace(spec))
	if req == "" || req == "auto" {
		for _, cand := range defaultPlayers {
			if p := lookAny(cand.bins); p != "" {
				return cand.kind, p, nil
			}
		}
		return "", "", errors.New("no supported local player found (install mpv, ffplay, IINA, or VLC, or run `tp-ipc live` without --player for the built-in web console)")
	}

	for _, cand := range defaultPlayers {
		if req == cand.kind {
			if p := lookAny(cand.bins); p != "" {
				return cand.kind, p, nil
			}
			return "", "", fmt.Errorf("player %q not found in PATH", spec)
		}
	}

	p, lookErr := exec.LookPath(spec)
	if lookErr != nil {
		return "", "", fmt.Errorf("player %q not found: %w", spec, lookErr)
	}
	base := strings.ToLower(filepath.Base(p))
	switch {
	case strings.Contains(base, "ffplay"):
		return "ffplay", p, nil
	case strings.Contains(base, "mpv"):
		return "mpv", p, nil
	case strings.Contains(base, "iina"):
		return "iina", p, nil
	case strings.Contains(base, "vlc"):
		return "vlc", p, nil
	default:
		return "custom", p, nil
	}
}

func lookAny(candidates []string) string {
	for _, c := range candidates {
		if filepath.IsAbs(c) {
			if st, err := os.Stat(c); err == nil && !st.IsDir() && (st.Mode()&0o111) != 0 {
				return c
			}
			continue
		}
		if p, err := exec.LookPath(c); err == nil {
			return p
		}
	}
	return ""
}

// LaunchPlayer opens the camera's live RTSP stream in a native desktop media player with low-latency flags.
func LaunchPlayer(ctx context.Context, client *ipc.Client, highQuality bool, playerSpec string, stdout io.Writer) error {
	cfg := client.Settings()
	if cfg.User == "" || cfg.Password == "" {
		return errors.New("camera credentials missing")
	}

	kind, binPath, err := ResolvePlayer(playerSpec)
	if err != nil {
		return err
	}

	stream := "stream2"
	qualityLabel := "SD sub-stream"
	if highQuality {
		stream = "stream1"
		qualityLabel = "4K main stream"
	}
	rtspURL, err := client.RTSPStreamURL(ctx, stream)
	if err != nil {
		return err
	}
	title := "tp-ipc live"
	if cfg.Name != "" {
		title = fmt.Sprintf("tp-ipc: %s (%s)", cfg.Name, qualityLabel)
	} else if cfg.Host != "" {
		title = fmt.Sprintf("tp-ipc: %s (%s)", cfg.Host, qualityLabel)
	}

	var args []string
	switch kind {
	case "ffplay":
		args = []string{
			"-nostdin",
			"-hide_banner",
			"-loglevel", "error",
			"-rtsp_transport", "tcp",
			"-fflags", "nobuffer",
			"-flags", "low_delay",
			"-framedrop",
			"-window_title", title,
			rtspURL,
		}
	case "mpv":
		args = []string{
			"--no-terminal",
			"--rtsp-transport=tcp",
			"--profile=low-latency",
			"--no-cache",
			"--untimed",
			"--title=" + title,
			rtspURL,
		}
	case "iina":
		args = []string{
			"--no-stdin",
			"--keep-running",
			"--mpv-rtsp-transport=tcp",
			"--mpv-profile=low-latency",
			"--mpv-title=" + title,
			rtspURL,
		}
	case "vlc":
		args = []string{
			"--rtsp-tcp",
			"--network-caching=300",
			rtspURL,
		}
	default:
		args = []string{rtspURL}
	}

	if stdout != nil {
		fmt.Fprintf(stdout, "Launching %s (%s) for %s...\n", kind, qualityLabel, cfg.RTSPURL(stream, true))
	}

	cmd := exec.CommandContext(ctx, binPath, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()
	if ctx.Err() != nil {
		return nil
	}
	if err != nil {
		redacted := strings.TrimSpace(client.Redact(stderr.String()))
		if redacted != "" {
			return fmt.Errorf("%s exited with error: %s", kind, redacted)
		}
		return fmt.Errorf("%s exited with error: %s", kind, client.Redact(err.Error()))
	}
	return nil
}

// OpenBrowser best-effort opens url in the user's default desktop browser.
func OpenBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return errors.New("no desktop display detected")
		}
		cmd = exec.Command("xdg-open", url)
	default:
		return fmt.Errorf("auto-open unsupported on %s", runtime.GOOS)
	}
	return cmd.Start()
}
