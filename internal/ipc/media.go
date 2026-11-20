package ipc

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type SnapshotOptions struct {
	HighQuality bool
	Zoom        int
	FocusX      float64
	FocusY      float64
}

type RecordResult struct {
	Path    string `json:"path"`
	Bytes   int64  `json:"bytes"`
	Seconds int    `json:"seconds"`
	Quality string `json:"quality"`
}

type TalkResult struct {
	SentRTPPackets int `json:"sent_rtp_packets"`
	SentBytes      int `json:"sent_bytes"`
}

func ensureFFmpeg() (string, error) {
	p, err := exec.LookPath("ffmpeg")
	if err != nil {
		return "", errors.New("ffmpeg not found in PATH (required for snapshot, clip recording, and audio talkback)")
	}
	return p, nil
}

// Snapshot captures a single JPEG frame from RTSP (/stream1 for 4K or digital zoom, /stream2 for fast 640x360).
func (c *Client) Snapshot(ctx context.Context, opts SnapshotOptions) ([]byte, error) {
	if c.cfg.User == "" || c.cfg.Password == "" {
		return nil, errors.New("camera credentials missing")
	}
	if opts.Zoom == 0 {
		opts.Zoom = 1
	}
	if opts.Zoom < 1 || opts.Zoom > 5 {
		return nil, errors.New("zoom must be between 1 and 5")
	}
	if math.IsNaN(opts.FocusX) || math.IsInf(opts.FocusX, 0) || opts.FocusX < 0 || opts.FocusX > 1 ||
		math.IsNaN(opts.FocusY) || math.IsInf(opts.FocusY, 0) || opts.FocusY < 0 || opts.FocusY > 1 {
		return nil, errors.New("focus_x and focus_y must be within [0, 1]")
	}
	ffmpegBin, err := ensureFFmpeg()
	if err != nil {
		return nil, err
	}

	stream := "stream2"
	if opts.HighQuality || opts.Zoom > 1 {
		stream = "stream1"
	}
	rtspURL, err := c.RTSPStreamURL(ctx, stream)
	if err != nil {
		return nil, err
	}

	args := []string{
		"-nostdin",
		"-v", "error",
		"-rtsp_transport", "tcp",
		"-i", rtspURL,
	}
	if opts.Zoom > 1 {
		filter := fmt.Sprintf("crop=iw/%d:ih/%d:(iw-iw/%d)*%.4f:(ih-ih/%d)*%.4f",
			opts.Zoom, opts.Zoom, opts.Zoom, opts.FocusX, opts.Zoom, opts.FocusY)
		args = append(args, "-vf", filter)
	}
	args = append(args, "-frames:v", "1", "-q:v", "2", "-f", "image2pipe", "-vcodec", "mjpeg", "pipe:1")

	snapCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(snapCtx, ffmpegBin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		errMsg := strings.TrimSpace(c.Redact(stderr.String()))
		if errors.Is(snapCtx.Err(), context.DeadlineExceeded) {
			return nil, errors.New("RTSP snapshot timed out")
		}
		if errMsg != "" {
			return nil, fmt.Errorf("RTSP snapshot failed: %s", errMsg)
		}
		return nil, fmt.Errorf("RTSP snapshot failed: %s", c.Redact(err.Error()))
	}
	data := stdout.Bytes()
	if len(data) == 0 {
		return nil, errors.New("RTSP snapshot produced empty output")
	}
	if len(data) > 8*1024*1024 {
		return nil, errors.New("snapshot exceeds 8 MiB safety limit")
	}
	return data, nil
}

// RecordClip records an RTSP video/audio clip without video transcoding.
// If outputPath is empty, generates a timestamped .mkv inside mediaDir.
func (c *Client) RecordClip(ctx context.Context, seconds int, highQuality bool, outputPath string, mediaDir string) (RecordResult, error) {
	if c.cfg.User == "" || c.cfg.Password == "" {
		return RecordResult{}, errors.New("camera credentials missing")
	}
	if seconds < 1 || seconds > 300 {
		return RecordResult{}, errors.New("clip duration must be between 1 and 300 seconds")
	}
	ffmpegBin, err := ensureFFmpeg()
	if err != nil {
		return RecordResult{}, err
	}

	targetPath := strings.TrimSpace(outputPath)
	if targetPath == "" {
		dir := strings.TrimSpace(mediaDir)
		if dir == "" {
			dir = strings.TrimSpace(c.cfg.MediaDir)
		}
		if dir == "" {
			return RecordResult{}, errors.New("output path or IPC_MEDIA_DIR is required for clip recording")
		}
		absDir, err := filepath.Abs(dir)
		if err != nil {
			return RecordResult{}, fmt.Errorf("invalid media directory: %w", err)
		}
		st, err := os.Stat(absDir)
		if err != nil || !st.IsDir() {
			return RecordResult{}, fmt.Errorf("media directory %s does not exist or is not a directory", absDir)
		}
		var suffix [4]byte
		_, _ = rand.Read(suffix[:])
		targetPath = filepath.Join(absDir, fmt.Sprintf("ipc-%d-%s.mkv", time.Now().Unix(), hex.EncodeToString(suffix[:])))
	} else {
		absTarget, err := filepath.Abs(targetPath)
		if err != nil {
			return RecordResult{}, err
		}
		targetPath = absTarget
		if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
			return RecordResult{}, fmt.Errorf("create output directory: %w", err)
		}
	}

	stream := "stream2"
	qualityLabel := "sub"
	if highQuality {
		stream = "stream1"
		qualityLabel = "main"
	}
	rtspURL, err := c.RTSPStreamURL(ctx, stream)
	if err != nil {
		return RecordResult{}, err
	}

	ext := strings.ToLower(filepath.Ext(targetPath))
	if ext == "" {
		ext = ".mkv"
	}
	partialPath := uniquePartialPath(targetPath, ext)
	defer os.Remove(partialPath)

	args := []string{
		"-nostdin",
		"-v", "error",
		"-rtsp_transport", "tcp",
		"-i", rtspURL,
		"-t", strconv.Itoa(seconds),
		"-map", "0:v:0",
		"-map", "0:a?",
	}
	if ext == ".mp4" {
		// Camera RTSP audio is pcm_alaw (G.711a), which MP4 containers reject without AAC audio encoding
		args = append(args, "-c:v", "copy", "-c:a", "aac")
	} else {
		args = append(args, "-c", "copy")
	}
	args = append(args, "-y", partialPath)

	recCtx, cancel := context.WithTimeout(ctx, time.Duration(seconds+15)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(recCtx, ffmpegBin, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		errMsg := strings.TrimSpace(c.Redact(stderr.String()))
		if errors.Is(recCtx.Err(), context.DeadlineExceeded) {
			return RecordResult{}, errors.New("RTSP clip recording timed out")
		}
		if errMsg != "" {
			return RecordResult{}, fmt.Errorf("RTSP recording failed: %s", errMsg)
		}
		return RecordResult{}, fmt.Errorf("RTSP recording failed: %s", c.Redact(err.Error()))
	}

	st, err := os.Stat(partialPath)
	if err != nil || st.Size() == 0 {
		return RecordResult{}, errors.New("RTSP recording produced an empty file")
	}
	if err := os.Rename(partialPath, targetPath); err != nil {
		return RecordResult{}, fmt.Errorf("finalize clip file: %w", err)
	}
	return RecordResult{
		Path:    targetPath,
		Bytes:   st.Size(),
		Seconds: seconds,
		Quality: qualityLabel,
	}, nil
}

func uniquePartialPath(targetPath, ext string) string {
	var rnd [4]byte
	_, _ = rand.Read(rnd[:])
	base := filepath.Base(targetPath)
	return filepath.Join(
		filepath.Dir(targetPath),
		fmt.Sprintf(".%s.%d-%s.partial%s", base, os.Getpid(), hex.EncodeToString(rnd[:]), ext),
	)
}

// PlayAudioFile streams a local audio file (.wav, .mp3, .m4a, .ogg, .aac, .flac) through the camera speaker via RTSP MULTITRANS.
func (c *Client) PlayAudioFile(ctx context.Context, filePath string) (TalkResult, error) {
	if c.cfg.User == "" || c.cfg.Password == "" {
		return TalkResult{}, errors.New("camera credentials missing")
	}
	ffmpegBin, err := ensureFFmpeg()
	if err != nil {
		return TalkResult{}, err
	}

	info, err := os.Stat(filePath)
	if err != nil || !info.Mode().IsRegular() {
		return TalkResult{}, fmt.Errorf("audio file %s is not a regular file", filePath)
	}
	if info.Size() == 0 || info.Size() > 15*1024*1024 {
		return TalkResult{}, errors.New("audio file must be non-empty and at most 15 MiB")
	}
	switch strings.ToLower(filepath.Ext(filePath)) {
	case ".wav", ".mp3", ".m4a", ".ogg", ".aac", ".flac", ".opus":
	default:
		return TalkResult{}, fmt.Errorf("unsupported audio extension %q", filepath.Ext(filePath))
	}

	rtspAddr := net.JoinHostPort(c.cfg.Host, strconv.Itoa(c.cfg.RTSPPort))
	conn, err := c.dialWithTimeout(ctx, "tcp", rtspAddr, 10*time.Second)
	if err != nil {
		return TalkResult{}, fmt.Errorf("connect camera RTSP talkback (%s): %s", rtspAddr, c.Redact(err.Error()))
	}
	defer conn.Close()

	uuid, err := randomUUID()
	if err != nil {
		return TalkResult{}, err
	}

	uriHost := c.cfg.Host
	if strings.Contains(uriHost, ":") && !strings.HasPrefix(uriHost, "[") {
		uriHost = "[" + uriHost + "]"
	}
	uri := "rtsp://" + uriHost + "/multitrans"
	prefix := "MULTITRANS " + uri + " RTSP/1.0\r\n"

	status, headers, _, err := rtspExchange(conn, prefix+"CSeq: 0\r\nX-Client-UUID: "+uuid+"\r\n\r\n")
	if err != nil {
		return TalkResult{}, err
	}
	if status == 401 {
		authHeader, err := buildRTSPAuthHeader(headers, "MULTITRANS", uri, c.cfg.User, c.cfg.Password)
		if err != nil {
			return TalkResult{}, err
		}
		status, headers, _, err = rtspExchange(conn,
			prefix+"CSeq: 1\r\nAuthorization: "+authHeader+"\r\nX-Client-UUID: "+uuid+"\r\n\r\n")
		if err != nil {
			return TalkResult{}, err
		}
	}
	if status != 200 {
		return TalkResult{}, fmt.Errorf("RTSP MULTITRANS authentication rejected (RTSP %d)", status)
	}

	session := rtspHeaderValue(headers, "Session")
	if idx := strings.IndexByte(session, ';'); idx >= 0 {
		session = strings.TrimSpace(session[:idx])
	}
	if session == "" {
		return TalkResult{}, errors.New("RTSP MULTITRANS response missing Session header")
	}

	talkReq := `{"type":"request","seq":0,"params":{"method":"get","talk":{"mode":"half_duplex"}}}`
	status, _, talkBody, err := rtspExchange(conn, fmt.Sprintf(
		"%sCSeq: 2\r\nSession: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		prefix, session, len(talkReq), talkReq,
	))
	if err != nil {
		return TalkResult{}, err
	}
	if status != 200 {
		return TalkResult{}, fmt.Errorf("RTSP talkback setup rejected (RTSP %d)", status)
	}
	var talkResp struct {
		Params struct {
			ErrorCode int `json:"error_code"`
		} `json:"params"`
	}
	if err := json.Unmarshal(talkBody, &talkResp); err != nil || talkResp.Params.ErrorCode != 0 {
		return TalkResult{}, fmt.Errorf("camera talkback channel unavailable (error_code %d)", talkResp.Params.ErrorCode)
	}

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return TalkResult{}, fmt.Errorf("bind local RTP socket: %w", err)
	}
	defer udpConn.Close()
	localPort := udpConn.LocalAddr().(*net.UDPAddr).Port

	playCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()

	rtpTarget := fmt.Sprintf("rtp://127.0.0.1:%d", localPort)
	cmd := exec.CommandContext(playCtx, ffmpegBin,
		"-nostdin", "-v", "error", "-re", "-i", filePath,
		"-vn", "-ac", "1", "-ar", "8000", "-c:a", "pcm_alaw", "-f", "rtp", rtpTarget,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return TalkResult{}, fmt.Errorf("start ffmpeg for talkback: %w", err)
	}

	doneCh := make(chan error, 1)
	go func() {
		doneCh <- cmd.Wait()
	}()

	buf := make([]byte, 4096)
	frame := make([]byte, 4+4096)
	packets := 0
	totalBytes := 0
	idleCount := 0
	ffmpegDone := false
	var ffmpegErr error

	for {
		if err := playCtx.Err(); err != nil {
			_ = cmd.Process.Kill()
			return TalkResult{}, errors.New("audio talkback timed out or canceled")
		}
		_ = udpConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, _, readErr := udpConn.ReadFromUDP(buf)
		if n > 0 {
			frame[0] = '$'
			frame[1] = 1
			frame[2] = byte((n >> 8) & 0xff)
			frame[3] = byte(n & 0xff)
			copy(frame[4:4+n], buf[:n])
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := writeAll(conn, frame[:4+n]); err != nil {
				_ = cmd.Process.Kill()
				return TalkResult{}, fmt.Errorf("send RTP talkback frame: %w", err)
			}
			packets++
			totalBytes += n
			idleCount = 0
		} else if readErr != nil {
			var netErr net.Error
			if errors.As(readErr, &netErr) && netErr.Timeout() {
				idleCount++
			} else {
				_ = cmd.Process.Kill()
				return TalkResult{}, fmt.Errorf("read local RTP socket: %w", readErr)
			}
		}

		if !ffmpegDone {
			select {
			case ffmpegErr = <-doneCh:
				ffmpegDone = true
			default:
			}
		}
		if ffmpegDone && idleCount >= 3 {
			break
		}
	}

	if ffmpegErr != nil {
		msg := strings.TrimSpace(c.Redact(stderr.String()))
		if msg != "" {
			return TalkResult{}, fmt.Errorf("ffmpeg audio encoding failed: %s", msg)
		}
		return TalkResult{}, fmt.Errorf("ffmpeg audio encoding failed: %w", ffmpegErr)
	}
	if packets == 0 {
		return TalkResult{}, errors.New("no RTP audio packets were produced")
	}
	return TalkResult{
		SentRTPPackets: packets,
		SentBytes:      totalBytes,
	}, nil
}

func randomUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

func rtspExchange(conn net.Conn, request string) (int, []string, []byte, error) {
	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
	if err := writeAll(conn, []byte(request)); err != nil {
		return 0, nil, nil, fmt.Errorf("RTSP write failed: %w", err)
	}

	var buf bytes.Buffer
	tmp := make([]byte, 2048)
	headerEnd := -1
	for headerEnd < 0 {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
			headerEnd = bytes.Index(buf.Bytes(), []byte("\r\n\r\n"))
			if buf.Len() > 65536 {
				return 0, nil, nil, errors.New("RTSP response header too large")
			}
		}
		if err != nil {
			return 0, nil, nil, fmt.Errorf("RTSP read header failed: %w", err)
		}
	}

	raw := buf.Bytes()
	headerBlock := string(raw[:headerEnd])
	lines := strings.Split(headerBlock, "\r\n")
	if len(lines) == 0 {
		return 0, nil, nil, errors.New("empty RTSP status line")
	}
	var status int
	if _, err := fmt.Sscanf(lines[0], "RTSP/1.0 %d", &status); err != nil {
		return 0, nil, nil, fmt.Errorf("unexpected RTSP status line %q", lines[0])
	}

	contentLen := 0
	if cl := rtspHeaderValue(lines[1:], "Content-Length"); cl != "" {
		if n, err := strconv.Atoi(cl); err == nil && n >= 0 && n <= 1024*1024 {
			contentLen = n
		}
	}

	bodyStart := headerEnd + 4
	for buf.Len() < bodyStart+contentLen {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if err != nil {
			return status, lines[1:], nil, fmt.Errorf("RTSP read body failed: %w", err)
		}
	}
	body := append([]byte(nil), buf.Bytes()[bodyStart:bodyStart+contentLen]...)
	return status, lines[1:], body, nil
}

func rtspHeaderValue(headers []string, key string) string {
	prefix := strings.ToLower(key) + ":"
	for _, h := range headers {
		if strings.HasPrefix(strings.ToLower(h), prefix) {
			return strings.TrimSpace(h[len(prefix):])
		}
	}
	return ""
}

func rtspHeaderValues(headers []string, key string) []string {
	prefix := strings.ToLower(key) + ":"
	var out []string
	for _, h := range headers {
		if strings.HasPrefix(strings.ToLower(h), prefix) {
			out = append(out, strings.TrimSpace(h[len(prefix):]))
		}
	}
	return out
}

func quotedParam(header, key string) string {
	needle := key + `="`
	idx := strings.Index(header, needle)
	if idx < 0 {
		return ""
	}
	rest := header[idx+len(needle):]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return ""
	}
	return rest[:end]
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func buildRTSPAuthHeader(headers []string, method, uri, user, password string) (string, error) {
	challenges := rtspHeaderValues(headers, "WWW-Authenticate")
	for _, ch := range challenges {
		if strings.HasPrefix(ch, "Digest") {
			realm := quotedParam(ch, "realm")
			nonce := quotedParam(ch, "nonce")
			if realm == "" || nonce == "" {
				continue
			}
			ha1 := md5Hex(user + ":" + realm + ":" + password)
			ha2 := md5Hex(method + ":" + uri)
			resp := md5Hex(ha1 + ":" + nonce + ":" + ha2)
			return fmt.Sprintf(`Digest username=%q, realm=%q, nonce=%q, uri=%q, response=%q`,
				user, realm, nonce, uri, resp), nil
		}
	}
	for _, ch := range challenges {
		if strings.HasPrefix(ch, "Basic") {
			tok := base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
			return "Basic " + tok, nil
		}
	}
	return "", errors.New("RTSP server did not offer Digest or Basic authentication")
}
