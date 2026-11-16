package ipc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
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
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aur3l14no/tp-ipc-cli/internal/config"
)

type ExportRecordingOptions struct {
	Date       string // Optional base date YYYY-MM-DD when Start/End are HH:MM[:SS]
	Start      string // HH:MM, HH:MM:SS, YYYY-MM-DD HH:MM[:SS], RFC3339, or Unix seconds
	End        string // HH:MM, HH:MM:SS, YYYY-MM-DD HH:MM[:SS], RFC3339, or Unix seconds
	OutputPath string // Target .mp4 or .mkv path (if empty, auto-generated inside MediaDir)
	MediaDir   string // Fallback directory when OutputPath is empty
}

type ExportRecordingResult struct {
	Path             string  `json:"path"`
	Bytes            int64   `json:"bytes"`
	StartTime        string  `json:"start_time"`
	EndTime          string  `json:"end_time"`
	SelectedDuration int64   `json:"selected_duration_seconds"`
	MediaDuration    float64 `json:"media_duration_seconds"`
	GapDuration      int64   `json:"gap_duration_seconds"`
	Segments         int     `json:"segments"`
	CameraChunks     int     `json:"camera_chunks"`
}

type timeSpan struct {
	start int64
	end   int64
}

type avStreamConfig struct {
	VideoCodec        string `json:"video_codec"`
	AudioCodec        string `json:"audio_codec"`
	AudioSamplingRate int    `json:"audio_sampling_rate"`
	AudioChannels     int    `json:"audio_channels"`
	ExtraData         struct {
		AudioFmtp string `json:"audio_fmtp"`
	} `json:"extra_data"`
}

var hhmmRe = regexp.MustCompile(`^(\d{1,2}):(\d{2})(?::(\d{2}))?$`)

// ParseTimeWindow parses flexible user time range inputs into Unix timestamps.
func ParseTimeWindow(baseDate, startRaw, endRaw string, loc *time.Location) (int64, int64, error) {
	if loc == nil {
		loc = time.Local
	}
	baseDay := time.Now().In(loc)
	if strings.TrimSpace(baseDate) != "" {
		compact := strings.ReplaceAll(strings.TrimSpace(baseDate), "-", "")
		parsedDay, err := time.ParseInLocation("20060102", compact, loc)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid --date %q (expected YYYY-MM-DD)", baseDate)
		}
		baseDay = parsedDay
	}

	startUnix, err := parseFlexibleTime(startRaw, baseDay, loc)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid start time %q: %w", startRaw, err)
	}
	// Default end's base day to start's calendar day if --date wasn't explicitly needed
	endBase := time.Unix(startUnix, 0).In(loc)
	if strings.TrimSpace(baseDate) != "" {
		endBase = baseDay
	}
	endUnix, err := parseFlexibleTime(endRaw, endBase, loc)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid end time %q: %w", endRaw, err)
	}
	if endUnix <= startUnix {
		return 0, 0, errors.New("end time must be after start time")
	}
	if endUnix-startUnix > 6*3600 {
		return 0, 0, errors.New("maximum export window is 6 hours per run")
	}
	return startUnix, endUnix, nil
}

func parseFlexibleTime(raw string, baseDay time.Time, loc *time.Location) (int64, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, errors.New("empty timestamp")
	}
	// 1. Pure Unix timestamp (10 digits)
	if len(s) >= 9 && len(s) <= 11 && digitsOnlyRe.MatchString(s) {
		v, err := strconv.ParseInt(s, 10, 64)
		if err == nil && v > 946684800 {
			return v, nil
		}
	}
	// 2. HH:MM or HH:MM:SS relative to baseDay
	if m := hhmmRe.FindStringSubmatch(s); m != nil {
		hh, _ := strconv.Atoi(m[1])
		mm, _ := strconv.Atoi(m[2])
		ss := 0
		if m[3] != "" {
			ss, _ = strconv.Atoi(m[3])
		}
		if hh > 23 || mm > 59 || ss > 59 {
			return 0, errors.New("clock time out of range")
		}
		t := time.Date(baseDay.Year(), baseDay.Month(), baseDay.Day(), hh, mm, ss, 0, loc)
		return t.Unix(), nil
	}
	// 3. RFC3339
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.Unix(), nil
	}
	// 4. Local datetime layouts
	layouts := []string{
		"2006-01-02 15:04:05",
		"2006-01-02 15:04",
		"2006-01-02T15:04:05",
		"2006-01-02T15:04",
	}
	for _, layout := range layouts {
		if t, err := time.ParseInLocation(layout, s, loc); err == nil {
			return t.Unix(), nil
		}
	}
	return 0, errors.New("supported formats: HH:MM, HH:MM:SS, 'YYYY-MM-DD HH:MM[:SS]', RFC3339, or Unix seconds")
}

func planExportSegments(recordings []RecordingSegment, reqStart, reqEnd int64) ([]timeSpan, int64, int64) {
	var primary, other []RecordingSegment
	for _, r := range recordings {
		if r.EndUnix <= r.StartUnix {
			continue
		}
		if r.VideoType == 2 {
			primary = append(primary, r)
		} else if r.VideoType != 26 {
			other = append(other, r)
		}
	}
	source := primary
	if len(source) == 0 {
		source = other
	}
	// Also merge both if scheduled (1) + motion (2) coexist without full overlap
	if len(primary) > 0 && len(other) > 0 {
		source = append(append([]RecordingSegment{}, primary...), other...)
	}
	sort.Slice(source, func(i, j int) bool {
		if source[i].StartUnix != source[j].StartUnix {
			return source[i].StartUnix < source[j].StartUnix
		}
		return source[i].EndUnix < source[j].EndUnix
	})

	var spans []timeSpan
	coveredUntil := reqStart
	for _, row := range source {
		segStart := max64(reqStart, max64(row.StartUnix, coveredUntil))
		segEnd := min64(reqEnd, row.EndUnix)
		if segEnd <= segStart {
			continue
		}
		if len(spans) > 0 && segStart <= spans[len(spans)-1].end {
			if segEnd > spans[len(spans)-1].end {
				spans[len(spans)-1].end = segEnd
			}
		} else {
			spans = append(spans, timeSpan{start: segStart, end: segEnd})
		}
		if segEnd > coveredUntil {
			coveredUntil = segEnd
		}
	}

	var mediaDur int64
	for _, sp := range spans {
		mediaDur += sp.end - sp.start
	}
	selectedDur := reqEnd - reqStart
	gapDur := selectedDur - mediaDur
	if gapDur < 0 {
		gapDur = 0
	}
	return spans, mediaDur, gapDur
}

// DownloadRecording exports historical SD card video across [Start, End] into a local .mp4 or .mkv file.
func (c *Client) DownloadRecording(ctx context.Context, opts ExportRecordingOptions) (ExportRecordingResult, error) {
	if c.cfg.User == "" || c.cfg.Password == "" {
		return ExportRecordingResult{}, errors.New("camera credentials missing")
	}
	ffmpegBin, err := ensureFFmpeg()
	if err != nil {
		return ExportRecordingResult{}, err
	}

	startUnix, endUnix, err := ParseTimeWindow(opts.Date, opts.Start, opts.End, time.Local)
	if err != nil {
		return ExportRecordingResult{}, err
	}

	targetPath, err := c.resolveExportOutputPath(opts.OutputPath, opts.MediaDir, startUnix, endUnix)
	if err != nil {
		return ExportRecordingResult{}, err
	}

	// Collect all SD card segments for every local calendar date touched by [startUnix, endUnix]
	var allRecordings []RecordingSegment
	curDay := time.Unix(startUnix, 0).In(time.Local)
	curDay = time.Date(curDay.Year(), curDay.Month(), curDay.Day(), 0, 0, 0, 0, time.Local)
	endMoment := time.Unix(endUnix, 0).In(time.Local)
	for !curDay.After(endMoment) {
		dateStr := curDay.Format("2006-01-02")
		segs, err := c.ListRecordings(ctx, dateStr)
		if err != nil {
			return ExportRecordingResult{}, err
		}
		allRecordings = append(allRecordings, segs...)
		curDay = curDay.AddDate(0, 0, 1)
	}

	spans, plannedMediaDur, gapDur := planExportSegments(allRecordings, startUnix, endUnix)
	if len(spans) == 0 {
		return ExportRecordingResult{}, fmt.Errorf(
			"no SD card recordings found between %s and %s (run `tp-ipc recordings list %s` to inspect available segments)",
			time.Unix(startUnix, 0).In(time.Local).Format("2006-01-02 15:04:05"),
			time.Unix(endUnix, 0).In(time.Local).Format("2006-01-02 15:04:05"),
			time.Unix(startUnix, 0).In(time.Local).Format("2006-01-02"),
		)
	}

	userID, err := c.ensureUserID(ctx)
	if err != nil {
		return ExportRecordingResult{}, err
	}

	workDir, err := os.MkdirTemp("", "tp-ipc-export-*")
	if err != nil {
		return ExportRecordingResult{}, fmt.Errorf("create temp export dir: %w", err)
	}
	defer os.RemoveAll(workDir)

	hevcParams := make(map[byte][]byte)
	var tsPaths []string
	var tsDurations []float64
	totalChunks := 0
	var lastAV avStreamConfig
	var totalDelivered float64

	for i, sp := range spans {
		segPath := filepath.Join(workDir, fmt.Sprintf("seg-%04d.ts", i+1))
		delivered, chunks, avCfg, err := c.exportSpanToTS(ctx, ffmpegBin, userID, sp, segPath, hevcParams)
		if err != nil {
			return ExportRecordingResult{}, err
		}
		tsPaths = append(tsPaths, segPath)
		segDur := delivered
		if segDur <= 0 {
			segDur = float64(sp.end - sp.start)
		}
		tsDurations = append(tsDurations, segDur)
		totalDelivered += delivered
		totalChunks += chunks
		lastAV = avCfg
	}

	partialOut := uniquePartialPath(targetPath, filepath.Ext(targetPath))
	defer os.Remove(partialOut)

	if err := stitchTSSegments(ctx, ffmpegBin, workDir, tsPaths, tsDurations, lastAV, partialOut); err != nil {
		return ExportRecordingResult{}, err
	}

	st, err := os.Stat(partialOut)
	if err != nil || st.Size() < 512 {
		return ExportRecordingResult{}, errors.New("exported video file is empty or incomplete")
	}
	if err := os.Rename(partialOut, targetPath); err != nil {
		return ExportRecordingResult{}, fmt.Errorf("finalize output file: %w", err)
	}

	if totalDelivered <= 0 {
		totalDelivered = float64(plannedMediaDur)
	}
	return ExportRecordingResult{
		Path:             targetPath,
		Bytes:            st.Size(),
		StartTime:        time.Unix(startUnix, 0).In(time.Local).Format(time.RFC3339),
		EndTime:          time.Unix(endUnix, 0).In(time.Local).Format(time.RFC3339),
		SelectedDuration: endUnix - startUnix,
		MediaDuration:    math.Round(totalDelivered*100) / 100,
		GapDuration:      gapDur,
		Segments:         len(spans),
		CameraChunks:     totalChunks,
	}, nil
}

func (c *Client) resolveExportOutputPath(outputPath, mediaDir string, startUnix, endUnix int64) (string, error) {
	target := strings.TrimSpace(outputPath)
	if target == "" {
		dir := strings.TrimSpace(mediaDir)
		if dir == "" {
			dir = strings.TrimSpace(c.cfg.MediaDir)
		}
		if dir == "" {
			return "", errors.New("output path (-o) or IPC_MEDIA_DIR is required")
		}
		absDir, err := filepath.Abs(dir)
		if err != nil {
			return "", err
		}
		st, err := os.Stat(absDir)
		if err != nil || !st.IsDir() {
			return "", fmt.Errorf("media directory %s does not exist or is not a directory", absDir)
		}
		var suffix [3]byte
		_, _ = rand.Read(suffix[:])
		prefix := "sd"
		if safeName := config.SanitizeProfileToken(c.cfg.Name); safeName != "" && safeName != "default" {
			prefix = "sd-" + safeName
		}
		target = filepath.Join(absDir, fmt.Sprintf("%s-%s-%s-%s.mp4",
			prefix,
			time.Unix(startUnix, 0).In(time.Local).Format("20060102-150405"),
			time.Unix(endUnix, 0).In(time.Local).Format("150405"),
			hex.EncodeToString(suffix[:]),
		))
		if filepath.Dir(target) != absDir {
			return "", errors.New("resolved export path escaped media directory")
		}
		return target, nil
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	if ext := strings.ToLower(filepath.Ext(absTarget)); ext != ".mp4" && ext != ".mkv" {
		return "", fmt.Errorf("unsupported export extension %q (expected .mp4 or .mkv)", ext)
	}
	if err := os.MkdirAll(filepath.Dir(absTarget), 0o755); err != nil {
		return "", err
	}
	return absTarget, nil
}

type bufferedRTP struct {
	channel byte
	packet  []byte
}

type rtpRewriteState struct {
	chunkBase map[byte]uint32
	nextSeq   map[byte]uint16
	ssrc      map[byte]uint32
}

func newRTPRewriteState() *rtpRewriteState {
	return &rtpRewriteState{
		chunkBase: make(map[byte]uint32),
		nextSeq:   make(map[byte]uint16),
		ssrc:      make(map[byte]uint32),
	}
}

func (st *rtpRewriteState) resetChunkBases() {
	st.chunkBase = make(map[byte]uint32)
}

func (st *rtpRewriteState) rewrite(channel byte, pkt []byte, completedSec float64, av avStreamConfig) []byte {
	if len(pkt) < 12 || (pkt[0]>>6) != 2 {
		return pkt
	}
	out := append([]byte(nil), pkt...)
	inTS := binary.BigEndian.Uint32(pkt[4:8])
	base, ok := st.chunkBase[channel]
	if !ok {
		base = inTS
		st.chunkBase[channel] = base
	}
	clock := 90000.0
	if channel == 1 {
		sr := av.AudioSamplingRate
		if sr <= 0 {
			sr = 16
		}
		clock = float64(sr * 1000)
	}
	elapsedTicks := inTS - base
	outBase := uint32(math.Round(completedSec * clock))
	binary.BigEndian.PutUint32(out[4:8], outBase+elapsedTicks)

	inSeq := binary.BigEndian.Uint16(pkt[2:4])
	seq, hasSeq := st.nextSeq[channel]
	if !hasSeq {
		seq = inSeq
	}
	binary.BigEndian.PutUint16(out[2:4], seq)
	st.nextSeq[channel] = seq + 1

	inSSRC := binary.BigEndian.Uint32(pkt[8:12])
	ssrc, hasSSRC := st.ssrc[channel]
	if !hasSSRC {
		ssrc = inSSRC
		st.ssrc[channel] = ssrc
	}
	binary.BigEndian.PutUint32(out[8:12], ssrc)
	return out
}

func (c *Client) exportSpanToTS(
	ctx context.Context,
	ffmpegBin string,
	userID int,
	span timeSpan,
	outTSPath string,
	hevcParams map[byte][]byte,
) (float64, int, avStreamConfig, error) {
	targetSeconds := float64(span.end - span.start)
	chunkStart := span.start
	completedSeconds := 0.0
	chunks := 0

	var (
		avCfg       avStreamConfig
		videoPT     = -1
		audioPT     = -1
		pending     []bufferedRTP
		ffCmd       *exec.Cmd
		ffStdin     io.WriteCloser
		ffDoneCh    chan struct{}
		ffExitErr   error
		ffStderr    bytes.Buffer
		udpSender   *net.UDPConn
		videoPort   int
		audioPort   int
		sdpDir      string
		rewriter    = newRTPRewriteState()
		firstPackAt time.Time
	)

	isFFmpegDone := func() bool {
		if ffDoneCh == nil {
			return false
		}
		select {
		case <-ffDoneCh:
			return true
		default:
			return false
		}
	}

	defer func() {
		if udpSender != nil {
			_ = udpSender.Close()
		}
		if ffCmd != nil && ffCmd.Process != nil && !isFFmpegDone() {
			_ = ffCmd.Process.Kill()
		}
		if sdpDir != "" {
			_ = os.RemoveAll(sdpDir)
		}
	}()

	startFFmpegIfNeeded := func(forceNoAudio bool) error {
		if ffCmd != nil || videoPT < 0 {
			return nil
		}
		if audioPT < 0 && !forceNoAudio {
			if firstPackAt.IsZero() {
				firstPackAt = time.Now()
			}
			if time.Since(firstPackAt) < 900*time.Millisecond {
				return nil
			}
		}

		vp, ap, err := reserveTwoUDPPorts()
		if err != nil {
			return err
		}
		videoPort, audioPort = vp, ap

		sdpDir, err = os.MkdirTemp("", "tp-ipc-sdp-*")
		if err != nil {
			return err
		}
		sdpPath := filepath.Join(sdpDir, "clip.sdp")
		normAudio := normalizeRTPAudioCodec(avCfg.AudioCodec, audioPT)
		effectiveAudioPT := audioPT
		if normAudio == "" {
			effectiveAudioPT = -1
		}
		sdpText := buildPlaybackSDP(videoPort, audioPort, videoPT, effectiveAudioPT, avCfg, hevcParams)
		if err := os.WriteFile(sdpPath, []byte(sdpText), 0o600); err != nil {
			return err
		}

		args := []string{
			"-hide_banner",
			"-loglevel", "warning",
			"-protocol_whitelist", "file,udp,rtp",
			"-analyzeduration", "5000000",
			"-probesize", "5000000",
			"-i", sdpPath,
			"-map", "0:v:0",
		}
		if effectiveAudioPT >= 0 {
			args = append(args, "-map", "0:a:0?")
		}
		if effectiveAudioPT >= 0 && normAudio != "AAC" {
			args = append(args, "-c:v", "copy", "-c:a", "aac")
		} else {
			args = append(args, "-c", "copy")
		}
		args = append(args,
			"-t", strconv.FormatInt(span.end-span.start, 10),
			"-f", "mpegts",
			"-muxdelay", "0",
			"-y", outTSPath,
		)

		ffCmd = exec.CommandContext(ctx, ffmpegBin, args...)
		ffStdin, err = ffCmd.StdinPipe()
		if err != nil {
			return err
		}
		ffCmd.Stderr = &ffStderr
		if err := ffCmd.Start(); err != nil {
			return fmt.Errorf("start ffmpeg playback muxer: %w", err)
		}
		ffDoneCh = make(chan struct{})
		go func() {
			ffExitErr = ffCmd.Wait()
			close(ffDoneCh)
		}()

		udpSender, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			return err
		}
		// Allow ffmpeg time to parse clip.sdp and bind its local RTP UDP sockets
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(450 * time.Millisecond):
		}

		for _, item := range pending {
			sendRTPToFFmpeg(udpSender, item.channel, item.packet, videoPort, audioPort)
		}
		pending = nil
		return nil
	}

	for chunkStart < span.end {
		chunks++
		rewriter.resetChunkBases()

		chunkElapsed, cfg, err := c.streamSinglePlaybackChunk(
			ctx,
			userID,
			chunkStart,
			span.end,
			func(cfg avStreamConfig) {
				avCfg = cfg
			},
			func(ch byte, rawPkt []byte) (bool, error) {
				pt, ts, ok := parseRTPHeader(rawPkt)
				if !ok {
					return false, nil
				}
				if ch == 0 {
					captureHEVCParams(hevcParams, rawPkt)
					if videoPT < 0 {
						videoPT = int(pt)
					}
				} else if ch == 1 {
					if audioPT < 0 {
						audioPT = int(pt)
					}
				} else {
					return false, nil
				}
				_ = ts

				rewritten := rewriter.rewrite(ch, rawPkt, completedSeconds, avCfg)
				if ffCmd != nil {
					sendRTPToFFmpeg(udpSender, ch, rewritten, videoPort, audioPort)
				} else {
					pending = append(pending, bufferedRTP{channel: ch, packet: rewritten})
					if err := startFFmpegIfNeeded(false); err != nil {
						return false, err
					}
				}

				if isFFmpegDone() {
					if ffExitErr != nil {
						msg := strings.TrimSpace(c.Redact(ffStderr.String()))
						if msg != "" {
							return false, fmt.Errorf("ffmpeg playback muxer failed: %s", msg)
						}
						return false, fmt.Errorf("ffmpeg playback muxer exited abnormally: %s", c.Redact(ffExitErr.Error()))
					}
					return true, nil
				}
				return false, nil
			},
		)
		if avCfg.VideoCodec == "" && cfg.VideoCodec != "" {
			avCfg = cfg
		}
		if err != nil {
			return 0, chunks, avCfg, err
		}

		// Flush buffered packets if clip was < 0.9s or video-only
		if ffCmd == nil && videoPT >= 0 {
			if sErr := startFFmpegIfNeeded(true); sErr != nil {
				return 0, chunks, avCfg, sErr
			}
		}

		if isFFmpegDone() {
			if ffExitErr != nil {
				msg := strings.TrimSpace(c.Redact(ffStderr.String()))
				if msg != "" {
					return 0, chunks, avCfg, fmt.Errorf("ffmpeg playback muxer failed: %s", msg)
				}
				return 0, chunks, avCfg, fmt.Errorf("ffmpeg playback muxer exited abnormally: %s", c.Redact(ffExitErr.Error()))
			}
			completedSeconds = targetSeconds
			break
		}

		chunkTarget := float64(span.end - chunkStart)
		tolerance := math.Min(1.0, math.Max(0.25, chunkTarget*0.01))
		if chunkElapsed >= chunkTarget-tolerance {
			completedSeconds = targetSeconds
			break
		}
		if chunkElapsed < 0.5 {
			if chunkElapsed > 0 {
				completedSeconds += chunkElapsed
			}
			break
		}
		nextStart := min64(span.end, max64(chunkStart+1, chunkStart+int64(math.Round(chunkElapsed))))
		completedSeconds += float64(nextStart - chunkStart)
		if nextStart >= span.end {
			break
		}
		chunkStart = nextStart
		select {
		case <-ctx.Done():
			return 0, chunks, avCfg, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}

	if err := ctx.Err(); err != nil {
		return 0, chunks, avCfg, err
	}
	if ffCmd == nil {
		return 0, chunks, avCfg, errors.New("camera did not send any RTP video packets for the requested recording")
	}

	// Let UDP loopback drain into ffmpeg, then stop ffmpeg cleanly
	if !isFFmpegDone() {
		select {
		case <-ctx.Done():
			return 0, chunks, avCfg, ctx.Err()
		case <-time.After(600 * time.Millisecond):
		}
	}
	if udpSender != nil {
		_ = udpSender.Close()
		udpSender = nil
	}
	if ffStdin != nil {
		_, _ = ffStdin.Write([]byte("q\n"))
		_ = ffStdin.Close()
	}

	signaledStop := false
	if !isFFmpegDone() {
		if completedSeconds < targetSeconds && ffCmd.Process != nil {
			signaledStop = true
			_ = ffCmd.Process.Signal(os.Interrupt)
		}
		select {
		case <-ffDoneCh:
		case <-time.After(2 * time.Second):
			if ffCmd.Process != nil {
				signaledStop = true
				_ = ffCmd.Process.Signal(os.Interrupt)
			}
			select {
			case <-ffDoneCh:
			case <-time.After(2 * time.Second):
				if ffCmd.Process != nil {
					signaledStop = true
					_ = ffCmd.Process.Kill()
				}
				<-ffDoneCh
			}
		}
	}
	ffCmd = nil

	if err := ctx.Err(); err != nil {
		return 0, chunks, avCfg, err
	}
	if ffExitErr != nil && !signaledStop {
		msg := strings.TrimSpace(c.Redact(ffStderr.String()))
		if msg != "" {
			return 0, chunks, avCfg, fmt.Errorf("ffmpeg failed to mux SD playback stream: %s", msg)
		}
		return 0, chunks, avCfg, fmt.Errorf("ffmpeg playback muxer failed: %s", c.Redact(ffExitErr.Error()))
	}

	info, statErr := os.Stat(outTSPath)
	if statErr != nil || info.Size() < 512 {
		msg := strings.TrimSpace(c.Redact(ffStderr.String()))
		if msg != "" {
			return 0, chunks, avCfg, fmt.Errorf("ffmpeg failed to mux SD playback stream: %s", msg)
		}
		return 0, chunks, avCfg, errors.New("ffmpeg produced an empty segment during SD playback export")
	}
	if completedSeconds <= 0 {
		completedSeconds = math.Min(targetSeconds, 1.0)
	}
	return completedSeconds, chunks, avCfg, nil
}

func (c *Client) streamSinglePlaybackChunk(
	ctx context.Context,
	userID int,
	startUnix, endUnix int64,
	onReady func(avStreamConfig),
	onPacket func(channel byte, packet []byte) (stop bool, err error),
) (float64, avStreamConfig, error) {
	var avCfg avStreamConfig

	dialer := net.Dialer{Timeout: 8 * time.Second}
	rtspAddr := net.JoinHostPort(c.cfg.Host, strconv.Itoa(c.cfg.RTSPPort))
	conn, err := dialer.DialContext(ctx, "tcp", rtspAddr)
	if err != nil {
		return 0, avCfg, fmt.Errorf("connect RTSP MULTITRANS (%s): %w", rtspAddr, err)
	}
	defer conn.Close()
	stopCancelClose := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	defer stopCancelClose()

	authority := c.cfg.Host
	if strings.Contains(authority, ":") && !strings.HasPrefix(authority, "[") {
		authority = "[" + authority + "]"
	}
	uri := fmt.Sprintf("rtsp://%s:%d/multitrans", authority, c.cfg.RTSPPort)

	bodyMap := map[string]any{
		"type": "request",
		"seq":  1,
		"params": map[string]any{
			"method": "get",
			"playback": map[string]any{
				"client_id":  userID,
				"channels":   []int{0, 1},
				"scale":      "+1/1",
				"start_time": strconv.FormatInt(startUnix, 10),
				"end_time":   strconv.FormatInt(endUnix, 10),
				"event_type": []int{1, 2},
			},
		},
	}
	bodyBytes, _ := json.Marshal(bodyMap)

	basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(c.cfg.User+":"+c.cfg.Password))
	reqStr := fmt.Sprintf(
		"MULTITRANS %s RTSP/1.0\r\nCSeq: 1\r\nAuthorization: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s\r\n",
		uri, basicAuth, len(bodyBytes), string(bodyBytes),
	)

	_ = conn.SetWriteDeadline(time.Now().Add(6 * time.Second))
	if err := writeAll(conn, []byte(reqStr)); err != nil {
		if ctx.Err() != nil {
			return 0, avCfg, ctx.Err()
		}
		return 0, avCfg, err
	}

	const (
		maxMultitransHeaderBytes = 64 * 1024
		maxMultitransBodyBytes   = 1024 * 1024
	)

	var buf bytes.Buffer
	tmp := make([]byte, 8192)
	headerEnd := -1
	_ = conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	for headerEnd < 0 {
		n, rErr := conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
			headerEnd = bytes.Index(buf.Bytes(), []byte("\r\n\r\n"))
			if headerEnd < 0 && buf.Len() > maxMultitransHeaderBytes {
				return 0, avCfg, errors.New("MULTITRANS playback response header exceeds 64 KiB limit")
			}
		}
		if rErr != nil {
			if ctx.Err() != nil {
				return 0, avCfg, ctx.Err()
			}
			return 0, avCfg, fmt.Errorf("read MULTITRANS playback response: %w", rErr)
		}
	}
	if headerEnd > maxMultitransHeaderBytes {
		return 0, avCfg, errors.New("MULTITRANS playback response header exceeds 64 KiB limit")
	}

	hdrLines := strings.Split(string(buf.Bytes()[:headerEnd]), "\r\n")
	var status int
	if _, scanErr := fmt.Sscanf(hdrLines[0], "RTSP/1.0 %d", &status); scanErr != nil {
		return 0, avCfg, fmt.Errorf("unexpected MULTITRANS status line %q", hdrLines[0])
	}
	if status != 200 {
		return 0, avCfg, fmt.Errorf("camera playback MULTITRANS returned RTSP %d", status)
	}
	contentLen := 0
	if cl := rtspHeaderValue(hdrLines[1:], "Content-Length"); cl != "" {
		parsedLen, convErr := strconv.Atoi(cl)
		if convErr != nil || parsedLen < 0 || parsedLen > maxMultitransBodyBytes {
			return 0, avCfg, fmt.Errorf("invalid MULTITRANS Content-Length %q", cl)
		}
		contentLen = parsedLen
	}
	bodyStart := headerEnd + 4
	for buf.Len() < bodyStart+contentLen {
		n, rErr := conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if rErr != nil {
			if ctx.Err() != nil {
				return 0, avCfg, ctx.Err()
			}
			return 0, avCfg, fmt.Errorf("read MULTITRANS JSON body: %w", rErr)
		}
	}

	var readyResp struct {
		Params struct {
			ErrorCode int              `json:"error_code"`
			AVConfig  []map[string]any `json:"av_config"`
		} `json:"params"`
	}
	rawJSON := buf.Bytes()[bodyStart : bodyStart+contentLen]
	if err := json.Unmarshal(rawJSON, &readyResp); err != nil {
		return 0, avCfg, fmt.Errorf("invalid JSON in MULTITRANS playback response: %w", err)
	}
	if readyResp.Params.ErrorCode != 0 {
		return 0, avCfg, fmt.Errorf("camera rejected SD playback request (error_code %d)", readyResp.Params.ErrorCode)
	}
	if len(readyResp.Params.AVConfig) > 0 {
		m := readyResp.Params.AVConfig[0]
		avCfg.VideoCodec = jsonStr(m["video_codec"])
		avCfg.AudioCodec = jsonStr(m["audio_codec"])
		avCfg.AudioSamplingRate = jsonInt(m["audio_sampling_rate"], 16)
		avCfg.AudioChannels = jsonInt(m["audio_channels"], 1)
		avCfg.ExtraData.AudioFmtp = jsonStr(asMap(m["extra_data"])["audio_fmtp"])
	}
	onReady(avCfg)

	// Remaining bytes after JSON body already belong to the interleaved '$' stream
	streamBuf := append([]byte(nil), buf.Bytes()[bodyStart+contentLen:]...)
	var (
		hasFirstVideoTS bool
		firstVideoTS    uint32
		lastElapsed     float64
		chunkTarget     = float64(endUnix - startUnix)
	)

	consumeStream := func() (bool, error) {
		cursor := 0
		for cursor+4 <= len(streamBuf) {
			if streamBuf[cursor] != 0x24 {
				idx := bytes.IndexByte(streamBuf[cursor+1:], 0x24)
				if idx < 0 {
					keep := len(streamBuf) - 3
					if keep < cursor {
						keep = cursor
					}
					streamBuf = streamBuf[keep:]
					return false, nil
				}
				cursor += 1 + idx
				continue
			}
			pktLen := int(binary.BigEndian.Uint16(streamBuf[cursor+2 : cursor+4]))
			end := cursor + 4 + pktLen
			if end > len(streamBuf) {
				break
			}
			ch := streamBuf[cursor+1]
			pkt := streamBuf[cursor+4 : end]
			if ch == 0 {
				if _, ts, ok := parseRTPHeader(pkt); ok {
					if !hasFirstVideoTS {
						firstVideoTS = ts
						hasFirstVideoTS = true
					}
					lastElapsed = float64(ts-firstVideoTS) / 90000.0
				}
			}
			stop, cbErr := onPacket(ch, pkt)
			if cbErr != nil {
				return false, cbErr
			}
			if stop || lastElapsed >= chunkTarget+5.0 {
				return true, nil
			}
			cursor = end
		}
		if cursor > 0 {
			streamBuf = append([]byte(nil), streamBuf[cursor:]...)
		}
		return false, nil
	}

	if done, err := consumeStream(); err != nil || done {
		return lastElapsed, avCfg, err
	}

	for {
		if err := ctx.Err(); err != nil {
			return lastElapsed, avCfg, err
		}
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, rErr := conn.Read(tmp)
		if n > 0 {
			streamBuf = append(streamBuf, tmp[:n]...)
			done, pErr := consumeStream()
			if pErr != nil || done {
				return lastElapsed, avCfg, pErr
			}
		}
		if rErr != nil {
			if ctx.Err() != nil {
				return lastElapsed, avCfg, ctx.Err()
			}
			if errors.Is(rErr, io.EOF) {
				return lastElapsed, avCfg, nil
			}
			var netErr net.Error
			if errors.As(rErr, &netErr) && netErr.Timeout() {
				// Camera stops sending RTP packets when an internal recording chunk ends
				return lastElapsed, avCfg, nil
			}
			return lastElapsed, avCfg, rErr
		}
	}
}

func stitchTSSegments(
	ctx context.Context,
	ffmpegBin string,
	workDir string,
	tsPaths []string,
	durations []float64,
	avCfg avStreamConfig,
	outputPath string,
) error {
	var manifest strings.Builder
	for i, p := range tsPaths {
		fmt.Fprintf(&manifest, "file '%s'\n", filepath.Base(p))
		if i < len(durations) && durations[i] > 0 {
			dur := durations[i]
			if i+1 < len(tsPaths) {
				dur += 0.0001
			}
			fmt.Fprintf(&manifest, "duration %.6f\n", dur)
		}
	}
	manifestPath := filepath.Join(workDir, "concat.txt")
	if err := os.WriteFile(manifestPath, []byte(manifest.String()), 0o600); err != nil {
		return err
	}

	ext := strings.ToLower(filepath.Ext(outputPath))
	args := []string{
		"-nostdin",
		"-hide_banner",
		"-loglevel", "error",
		"-fflags", "+genpts",
		"-f", "concat",
		"-safe", "0",
		"-i", "concat.txt",
		"-map", "0:v:0",
		"-map", "0:a:0?",
		"-c", "copy",
	}
	if ext == ".mp4" {
		if strings.ToUpper(avCfg.VideoCodec) == "H265" || avCfg.VideoCodec == "" {
			args = append(args, "-tag:v", "hvc1")
		}
		args = append(args, "-movflags", "+faststart", "-avoid_negative_ts", "make_zero")
	} else {
		args = append(args, "-avoid_negative_ts", "make_zero")
	}
	args = append(args, "-y", outputPath)

	cmd := exec.CommandContext(ctx, ffmpegBin, args...)
	cmd.Dir = workDir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return fmt.Errorf("ffmpeg lossless stitch failed: %s", msg)
		}
		return fmt.Errorf("ffmpeg lossless stitch failed: %w", err)
	}
	return nil
}

func parseRTPHeader(pkt []byte) (payloadType byte, timestamp uint32, ok bool) {
	if len(pkt) < 12 || (pkt[0]>>6) != 2 {
		return 0, 0, false
	}
	return pkt[1] & 0x7f, binary.BigEndian.Uint32(pkt[4:8]), true
}

func rtpPayloadSlice(pkt []byte) []byte {
	if len(pkt) < 12 || (pkt[0]>>6) != 2 {
		return nil
	}
	csrcCount := int(pkt[0] & 0x0f)
	offset := 12 + csrcCount*4
	if pkt[0]&0x10 != 0 {
		if offset+4 > len(pkt) {
			return nil
		}
		extWords := int(binary.BigEndian.Uint16(pkt[offset+2 : offset+4]))
		offset += 4 + extWords*4
	}
	padding := 0
	if pkt[0]&0x20 != 0 {
		padding = int(pkt[len(pkt)-1])
	}
	if offset >= len(pkt) || padding > len(pkt)-offset {
		return nil
	}
	return pkt[offset : len(pkt)-padding]
}

func captureHEVCParams(params map[byte][]byte, pkt []byte) {
	payload := rtpPayloadSlice(pkt)
	if len(payload) < 2 {
		return
	}
	record := func(nal []byte) {
		if len(nal) < 2 {
			return
		}
		nalType := (nal[0] >> 1) & 0x3f
		if nalType >= 32 && nalType <= 34 {
			if _, exists := params[nalType]; !exists {
				params[nalType] = append([]byte(nil), nal...)
			}
		}
	}
	nalType := (payload[0] >> 1) & 0x3f
	if nalType != 48 {
		record(payload)
		return
	}
	offset := 2
	for offset+2 <= len(payload) {
		sz := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
		offset += 2
		if sz <= 0 || offset+sz > len(payload) {
			return
		}
		record(payload[offset : offset+sz])
		offset += sz
	}
}

func normalizeRTPAudioCodec(raw string, payloadType int) string {
	cleaned := strings.ToUpper(strings.TrimSpace(raw))
	cleaned = strings.NewReplacer(".", "", "-", "", "_", "").Replace(cleaned)
	switch cleaned {
	case "AAC", "MPEG4GENERIC":
		return "AAC"
	case "PCMA", "G711A", "G711", "G711ALAW", "PCMALAW", "ALAW":
		return "PCMA"
	case "PCMU", "G711U", "G711ULAW", "PCMULAW", "ULAW":
		return "PCMU"
	case "OPUS":
		return "OPUS"
	case "NONE", "OFF", "DISABLED":
		return ""
	case "":
		if payloadType == 8 {
			return "PCMA"
		}
		if payloadType == 0 {
			return "PCMU"
		}
		return "AAC"
	default:
		if payloadType == 8 {
			return "PCMA"
		}
		if payloadType == 0 {
			return "PCMU"
		}
		return ""
	}
}

func buildPlaybackSDP(
	videoPort, audioPort int,
	videoPT, audioPT int,
	av avStreamConfig,
	hevcParams map[byte][]byte,
) string {
	videoCodec := strings.ToUpper(strings.TrimSpace(av.VideoCodec))
	if videoCodec == "" {
		videoCodec = "H265"
	}
	audioCodec := normalizeRTPAudioCodec(av.AudioCodec, audioPT)
	sampleRate := av.AudioSamplingRate
	if sampleRate <= 0 {
		if audioCodec == "PCMA" || audioCodec == "PCMU" {
			sampleRate = 8
		} else {
			sampleRate = 16
		}
	}
	sampleRate *= 1000
	channels := av.AudioChannels
	if channels <= 0 {
		channels = 1
	}

	fmtp := strings.TrimSpace(av.ExtraData.AudioFmtp)
	if idx := strings.Index(strings.ToLower(fmtp), "a=fmtp:"); idx == 0 {
		if sp := strings.IndexByte(fmtp, ' '); sp > 0 {
			fmtp = strings.TrimSpace(fmtp[sp+1:])
		}
	}
	fmtp = strings.NewReplacer(
		"size-length", "sizelength",
		"index-length", "indexlength",
		"index-delta-length", "indexdeltalength",
	).Replace(fmtp)

	audioRTPMap := fmt.Sprintf("%s/%d/%d", audioCodec, sampleRate, channels)
	if audioCodec == "AAC" {
		audioRTPMap = fmt.Sprintf("MPEG4-GENERIC/%d/%d", sampleRate, channels)
	}

	lines := []string{
		"v=0",
		"o=- 0 0 IN IP4 127.0.0.1",
		"s=TP IPC clip export",
		"c=IN IP4 127.0.0.1",
		"t=0 0",
		fmt.Sprintf("m=video %d RTP/AVP %d", videoPort, videoPT),
		fmt.Sprintf("a=rtpmap:%d %s/90000", videoPT, videoCodec),
	}
	if videoCodec == "H265" && len(hevcParams[32]) > 0 && len(hevcParams[33]) > 0 && len(hevcParams[34]) > 0 {
		lines = append(lines, fmt.Sprintf("a=fmtp:%d sprop-vps=%s;sprop-sps=%s;sprop-pps=%s",
			videoPT,
			base64.StdEncoding.EncodeToString(hevcParams[32]),
			base64.StdEncoding.EncodeToString(hevcParams[33]),
			base64.StdEncoding.EncodeToString(hevcParams[34]),
		))
	}
	lines = append(lines, "a=recvonly")

	if audioPT >= 0 && audioCodec != "" {
		lines = append(lines,
			fmt.Sprintf("m=audio %d RTP/AVP %d", audioPort, audioPT),
			fmt.Sprintf("a=rtpmap:%d %s", audioPT, audioRTPMap),
		)
		if fmtp != "" {
			lines = append(lines, fmt.Sprintf("a=fmtp:%d %s", audioPT, fmtp))
		}
		lines = append(lines, "a=recvonly")
	}
	return strings.Join(lines, "\r\n") + "\r\n"
}

func reserveTwoUDPPorts() (int, int, error) {
	var held []*net.UDPConn
	defer func() {
		for _, c := range held {
			_ = c.Close()
		}
	}()

	reservePair := func() (int, error) {
		for attempt := 0; attempt < 64; attempt++ {
			probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
			if err != nil {
				return 0, err
			}
			p := probe.LocalAddr().(*net.UDPAddr).Port
			if p%2 == 1 {
				// Keep odd socket in `held` during search so OS gives us fresh ports, or try p+1
				held = append(held, probe)
				evenPort := p + 1
				if evenPort >= 65534 {
					continue
				}
				rtpConn, err1 := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: evenPort})
				if err1 != nil {
					continue
				}
				rtcpConn, err2 := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: evenPort + 1})
				if err2 != nil {
					_ = rtpConn.Close()
					continue
				}
				held = append(held, rtpConn, rtcpConn)
				return evenPort, nil
			}
			rtcpConn, err2 := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: p + 1})
			if err2 != nil {
				held = append(held, probe)
				continue
			}
			held = append(held, probe, rtcpConn)
			return p, nil
		}
		return 0, errors.New("unable to reserve local RTP/RTCP UDP port pair")
	}

	p1, err := reservePair()
	if err != nil {
		return 0, 0, err
	}
	p2, err := reservePair()
	if err != nil {
		return 0, 0, err
	}
	return p1, p2, nil
}

func sendRTPToFFmpeg(conn *net.UDPConn, channel byte, pkt []byte, videoPort, audioPort int) {
	if conn == nil {
		return
	}
	port := videoPort
	if channel == 1 {
		port = audioPort
	}
	if port <= 0 {
		return
	}
	_, _ = conn.WriteToUDP(pkt, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
