package live

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/aur3l14no/tp-ipc-cli/internal/ipc"
)

const (
	maxMP4BoxBytes     = 32 * 1024 * 1024
	maxGOPCacheBytes   = 16 * 1024 * 1024
	maxGOPCacheFrags   = 150
	subscriberQueueLen = 192
	streamIdleGrace    = 3 * time.Second
)

// readMP4Box reads one complete top-level ISO BMFF box (header + payload) from r.
func readMP4Box(r io.Reader) ([]byte, string, error) {
	var hdr [8]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, "", err
	}
	size32 := binary.BigEndian.Uint32(hdr[0:4])
	typ := string(hdr[4:8])

	var totalSize uint64
	headerLen := 8
	var extHdr [8]byte

	switch size32 {
	case 0:
		return nil, "", errors.New("indefinite-size MP4 box is unsupported in live stream")
	case 1:
		if _, err := io.ReadFull(r, extHdr[:]); err != nil {
			return nil, "", err
		}
		totalSize = binary.BigEndian.Uint64(extHdr[:])
		headerLen = 16
	default:
		totalSize = uint64(size32)
	}

	if totalSize < uint64(headerLen) {
		return nil, "", fmt.Errorf("invalid MP4 box %q size %d", typ, totalSize)
	}
	if totalSize > maxMP4BoxBytes {
		return nil, "", fmt.Errorf("MP4 box %q (%d bytes) exceeds %d byte safety limit", typ, totalSize, maxMP4BoxBytes)
	}

	buf := make([]byte, int(totalSize))
	copy(buf[0:8], hdr[:])
	if headerLen == 16 {
		copy(buf[8:16], extHdr[:])
	}
	if _, err := io.ReadFull(r, buf[headerLen:]); err != nil {
		return nil, "", err
	}
	return buf, typ, nil
}

type mp4ChildBox struct {
	Type    string
	Payload []byte
}

func parseMP4Children(buf []byte) []mp4ChildBox {
	var out []mp4ChildBox
	pos := 0
	for pos+8 <= len(buf) {
		sz := uint64(binary.BigEndian.Uint32(buf[pos : pos+4]))
		typ := string(buf[pos+4 : pos+8])
		hdrLen := 8
		if sz == 1 {
			if pos+16 > len(buf) {
				break
			}
			sz = binary.BigEndian.Uint64(buf[pos+8 : pos+16])
			hdrLen = 16
		}
		if sz < uint64(hdrLen) || uint64(pos)+sz > uint64(len(buf)) {
			break
		}
		end := pos + int(sz)
		out = append(out, mp4ChildBox{
			Type:    typ,
			Payload: buf[pos+hdrLen : end],
		})
		pos = end
	}
	return out
}

// ExtractMimeFromMoov inspects a fragmented MP4 moov box and returns an RFC 6381 MIME type
// suitable for MediaSource.addSourceBuffer (e.g. `video/mp4; codecs="hvc1.1.6.L150.0, mp4a.40.2"`).
func ExtractMimeFromMoov(moovBox []byte) string {
	payload := moovBox
	if len(moovBox) >= 8 && string(moovBox[4:8]) == "moov" {
		payload = moovBox[8:]
	}

	var videoCodec string
	var audioCodec string

	var walk func(children []mp4ChildBox)
	walk = func(children []mp4ChildBox) {
		for _, box := range children {
			switch box.Type {
			case "trak", "mdia", "minf", "stbl":
				walk(parseMP4Children(box.Payload))
			case "stsd":
				if len(box.Payload) <= 8 {
					continue
				}
				for _, entry := range parseMP4Children(box.Payload[8:]) {
					switch entry.Type {
					case "avc1", "avc3":
						if len(entry.Payload) > 78 {
							for _, cfg := range parseMP4Children(entry.Payload[78:]) {
								if cfg.Type == "avcC" && len(cfg.Payload) >= 4 {
									videoCodec = fmt.Sprintf("%s.%02X%02X%02X", entry.Type, cfg.Payload[1], cfg.Payload[2], cfg.Payload[3])
								}
							}
						}
						if videoCodec == "" {
							videoCodec = "avc1.42E01F"
						}
					case "hvc1", "hev1":
						if len(entry.Payload) > 78 {
							for _, cfg := range parseMP4Children(entry.Payload[78:]) {
								if cfg.Type == "hvcC" && len(cfg.Payload) >= 13 {
									videoCodec = formatHEVCCodec(entry.Type, cfg.Payload)
								}
							}
						}
						if videoCodec == "" {
							videoCodec = entry.Type + ".1.6.L93.B0"
						}
					case "mp4a":
						audioCodec = "mp4a.40.2"
					}
				}
			}
		}
	}
	walk(parseMP4Children(payload))

	var codecs []string
	if videoCodec != "" {
		codecs = append(codecs, videoCodec)
	}
	if audioCodec != "" {
		codecs = append(codecs, audioCodec)
	}
	if len(codecs) == 0 {
		return `video/mp4; codecs="avc1.42E01F"`
	}
	return fmt.Sprintf(`video/mp4; codecs="%s"`, strings.Join(codecs, ", "))
}

func formatHEVCCodec(fourcc string, hvcC []byte) string {
	spaces := [4]string{"", "A", "B", "C"}
	profileSpace := spaces[(hvcC[1]>>6)&0x03]
	tier := 'L'
	if (hvcC[1] & 0x20) != 0 {
		tier = 'H'
	}
	profileIDC := hvcC[1] & 0x1f
	compat := bits.Reverse32(binary.BigEndian.Uint32(hvcC[2:6]))
	if compat == 0 {
		compat = 6
	}
	levelIDC := hvcC[12]

	constraints := hvcC[6:12]
	lastNonZero := 0
	for i := len(constraints) - 1; i >= 0; i-- {
		if constraints[i] != 0 {
			lastNonZero = i
			break
		}
	}
	var cParts []string
	for i := 0; i <= lastNonZero; i++ {
		cParts = append(cParts, fmt.Sprintf("%X", constraints[i]))
	}
	return fmt.Sprintf("%s.%s%d.%X.%c%d.%s",
		fourcc, profileSpace, profileIDC, compat, tier, levelIDC, strings.Join(cParts, "."))
}

// extractVideoTrackID finds the track_ID of the video ("vide") track inside moov (defaults to 1).
func extractVideoTrackID(moovBox []byte) uint32 {
	payload := moovBox
	if len(moovBox) >= 8 && string(moovBox[4:8]) == "moov" {
		payload = moovBox[8:]
	}
	for _, box := range parseMP4Children(payload) {
		if box.Type != "trak" {
			continue
		}
		var trackID uint32
		isVideo := false
		for _, child := range parseMP4Children(box.Payload) {
			if child.Type == "tkhd" && len(child.Payload) >= 20 {
				ver := child.Payload[0]
				if ver == 1 && len(child.Payload) >= 24 {
					trackID = binary.BigEndian.Uint32(child.Payload[20:24])
				} else {
					trackID = binary.BigEndian.Uint32(child.Payload[12:16])
				}
			}
			if child.Type == "mdia" {
				for _, m := range parseMP4Children(child.Payload) {
					if m.Type == "hdlr" && len(m.Payload) >= 12 && string(m.Payload[8:12]) == "vide" {
						isVideo = true
					}
				}
			}
		}
		if isVideo && trackID != 0 {
			return trackID
		}
	}
	return 1
}

// moofHasVideoSync reports whether a moof box contains a sync (keyframe) sample for videoTrackID.
func moofHasVideoSync(moofBox []byte, videoTrackID uint32) bool {
	payload := moofBox
	if len(moofBox) >= 8 && string(moofBox[4:8]) == "moof" {
		payload = moofBox[8:]
	}
	for _, box := range parseMP4Children(payload) {
		if box.Type != "traf" {
			continue
		}
		var trackID uint32
		var defaultFlags uint32
		hasDefaultFlags := false
		for _, t := range parseMP4Children(box.Payload) {
			if t.Type == "tfhd" && len(t.Payload) >= 8 {
				tfFlags := binary.BigEndian.Uint32(t.Payload[0:4]) & 0x00ffffff
				trackID = binary.BigEndian.Uint32(t.Payload[4:8])
				off := 8
				if tfFlags&0x01 != 0 {
					off += 8
				}
				if tfFlags&0x02 != 0 {
					off += 4
				}
				if tfFlags&0x08 != 0 {
					off += 4
				}
				if tfFlags&0x10 != 0 {
					off += 4
				}
				if tfFlags&0x20 != 0 && off+4 <= len(t.Payload) {
					defaultFlags = binary.BigEndian.Uint32(t.Payload[off : off+4])
					hasDefaultFlags = true
				}
			}
		}
		if trackID != videoTrackID {
			continue
		}
		for _, t := range parseMP4Children(box.Payload) {
			if t.Type != "trun" || len(t.Payload) < 8 {
				continue
			}
			trFlags := binary.BigEndian.Uint32(t.Payload[0:4]) & 0x00ffffff
			count := binary.BigEndian.Uint32(t.Payload[4:8])
			if count == 0 {
				continue
			}
			off := 8
			if trFlags&0x01 != 0 {
				off += 4
			}
			var firstSampleFlags uint32
			foundFlags := false
			if trFlags&0x04 != 0 && off+4 <= len(t.Payload) {
				firstSampleFlags = binary.BigEndian.Uint32(t.Payload[off : off+4])
				foundFlags = true
			} else if trFlags&0x400 != 0 {
				if trFlags&0x100 != 0 {
					off += 4
				}
				if trFlags&0x200 != 0 {
					off += 4
				}
				if off+4 <= len(t.Payload) {
					firstSampleFlags = binary.BigEndian.Uint32(t.Payload[off : off+4])
					foundFlags = true
				}
			} else if hasDefaultFlags {
				firstSampleFlags = defaultFlags
				foundFlags = true
			}
			// sample_is_non_sync_sample (0x00010000) == 0 and sample_depends_on != 1 (not disposable/non-I)
			if foundFlags && (firstSampleFlags&0x01010000) == 0 {
				return true
			}
		}
	}
	return false
}

type streamKey struct {
	camera  string
	quality string // "sub" or "main"
	codec   string // "copy" or "h264"
}

type streamHub struct {
	mu        sync.Mutex
	ffmpegBin string
	sessions  map[streamKey]*streamSession
}

func newStreamHub(ffmpegBin string) *streamHub {
	return &streamHub{
		ffmpegBin: ffmpegBin,
		sessions:  make(map[streamKey]*streamSession),
	}
}

func (h *streamHub) closeAll() {
	h.mu.Lock()
	list := make([]*streamSession, 0, len(h.sessions))
	for k, s := range h.sessions {
		list = append(list, s)
		delete(h.sessions, k)
	}
	h.mu.Unlock()
	for _, s := range list {
		s.stop()
	}
}

func (h *streamHub) resolveFFmpeg() (string, error) {
	if h.ffmpegBin != "" {
		return h.ffmpegBin, nil
	}
	p, err := exec.LookPath("ffmpeg")
	if err != nil {
		return "", errors.New("ffmpeg not found in PATH (required for live streaming)")
	}
	return p, nil
}

func (h *streamHub) subscribe(parentCtx context.Context, key streamKey, client *ipc.Client) (*streamSubscription, error) {
	ffmpegBin, err := h.resolveFFmpeg()
	if err != nil {
		return nil, err
	}
	cfg := client.Settings()
	if cfg.User == "" || cfg.Password == "" {
		return nil, errors.New("camera credentials missing")
	}

	h.mu.Lock()
	sess, ok := h.sessions[key]
	if !ok || sess.isDead() {
		sess = newStreamSession(h, key, ffmpegBin, client)
		h.sessions[key] = sess
		go sess.run()
	}
	sub := sess.addSubscriber()
	h.mu.Unlock()

	select {
	case <-sess.readyCh:
		if sess.initErr != nil {
			sess.removeSubscriber(sub)
			return nil, sess.initErr
		}
		return sub, nil
	case <-parentCtx.Done():
		sess.removeSubscriber(sub)
		return nil, parentCtx.Err()
	}
}

type streamSubscription struct {
	sess    *streamSession
	initSeg []byte
	mime    string
	ch      chan []byte
	doneCh  chan struct{}
}

func (s *streamSubscription) Close() {
	s.sess.removeSubscriber(s)
}

type streamSession struct {
	hub       *streamHub
	key       streamKey
	ffmpegBin string
	client    *ipc.Client

	ctx    context.Context
	cancel context.CancelFunc

	readyCh chan struct{}
	doneCh  chan struct{}

	mu           sync.Mutex
	dead         bool
	initSeg      []byte
	mime         string
	initErr      error
	videoTrackID uint32
	gopCache     [][]byte
	gopBytes     int
	subs         map[*streamSubscription]struct{}
	idleTimer    *time.Timer
}

func newStreamSession(hub *streamHub, key streamKey, ffmpegBin string, client *ipc.Client) *streamSession {
	ctx, cancel := context.WithCancel(context.Background())
	return &streamSession{
		hub:       hub,
		key:       key,
		ffmpegBin: ffmpegBin,
		client:    client,
		ctx:       ctx,
		cancel:    cancel,
		readyCh:   make(chan struct{}),
		doneCh:    make(chan struct{}),
		subs:      make(map[*streamSubscription]struct{}),
	}
}

func (s *streamSession) isDead() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dead
}

func (s *streamSession) stop() {
	s.cancel()
}

func (s *streamSession) addSubscriber() *streamSubscription {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.idleTimer != nil {
		s.idleTimer.Stop()
		s.idleTimer = nil
	}
	sub := &streamSubscription{
		sess:   s,
		ch:     make(chan []byte, subscriberQueueLen),
		doneCh: s.doneCh,
	}
	// If initSeg is already ready, populate initSeg, mime, and prime GOP cache immediately under lock!
	if len(s.initSeg) > 0 {
		sub.initSeg = s.initSeg
		sub.mime = s.mime
		for _, frag := range s.gopCache {
			select {
			case sub.ch <- frag:
			default:
			}
		}
	}
	s.subs[sub] = struct{}{}
	return sub
}

func (s *streamSession) removeSubscriber(sub *streamSubscription) {
	s.mu.Lock()
	delete(s.subs, sub)
	remaining := len(s.subs)
	if remaining == 0 && !s.dead && s.idleTimer == nil {
		s.idleTimer = time.AfterFunc(streamIdleGrace, func() {
			s.mu.Lock()
			empty := len(s.subs) == 0
			s.mu.Unlock()
			if empty {
				s.cancel()
			}
		})
	}
	s.mu.Unlock()
}

func (s *streamSession) buildFFmpegArgs(rtspURL string, tagHVC1 bool) []string {
	args := []string{
		"-nostdin",
		"-hide_banner",
		"-loglevel", "error",
		"-rtsp_transport", "tcp",
		"-fflags", "+genpts",
		"-i", rtspURL,
		"-map", "0:v:0",
		"-map", "0:a:0?",
	}
	if s.key.codec == "h264" {
		args = append(args,
			"-vf", "scale='min(1920,iw)':-2",
			"-c:v", "libx264",
			"-preset", "ultrafast",
			"-tune", "zerolatency",
			"-profile:v", "baseline",
			"-pix_fmt", "yuv420p",
			"-crf", "25",
			"-maxrate", "3M",
			"-bufsize", "6M",
			"-g", "30",
		)
	} else {
		args = append(args, "-c:v", "copy")
		if tagHVC1 {
			args = append(args, "-tag:v", "hvc1")
		} else {
			// Strip degenerate type-0 / trailing-zero NALs emitted by some TL-IPC H.264 streams
			// that otherwise become 0-length AVCC units rejected by Chromium MSE.
			args = append(args, "-bsf:v", "filter_units=remove_types=0")
		}
	}
	args = append(args,
		"-c:a", "aac",
		"-ar", "16000",
		"-ac", "1",
		"-b:a", "32k",
		"-af", "aresample=async=1:first_pts=0",
		"-frag_duration", "100000",
		"-movflags", "empty_moov+default_base_moof+skip_trailer",
		"-flush_packets", "1",
		"-f", "mp4",
		"pipe:1",
	)
	return args
}

func (s *streamSession) run() {
	defer func() {
		s.mu.Lock()
		s.dead = true
		if s.idleTimer != nil {
			s.idleTimer.Stop()
		}
		s.mu.Unlock()

		s.hub.mu.Lock()
		if cur, ok := s.hub.sessions[s.key]; ok && cur == s {
			delete(s.hub.sessions, s.key)
		}
		s.hub.mu.Unlock()

		close(s.doneCh)
	}()

	readySignaled := false
	signalReady := func(err error) {
		if !readySignaled {
			if err != nil {
				s.mu.Lock()
				s.initErr = err
				s.mu.Unlock()
			}
			readySignaled = true
			close(s.readyCh)
		}
	}

	streamName := "stream2"
	if s.key.quality == "main" {
		streamName = "stream1"
	}
	rtspURL, err := s.client.RTSPStreamURL(s.ctx, streamName)
	if err != nil {
		signalReady(err)
		return
	}

	tagHVC1 := s.key.codec != "h264"
	shouldRetryNoTag, err := s.streamOnce(rtspURL, tagHVC1, signalReady)
	if shouldRetryNoTag && s.ctx.Err() == nil {
		_, err = s.streamOnce(rtspURL, false, signalReady)
	}
	if !readySignaled {
		if err == nil {
			err = errors.New("live stream ended before initialization")
		}
		signalReady(err)
	}
}

func (s *streamSession) streamOnce(rtspURL string, tagHVC1 bool, signalReady func(error)) (retryWithoutTag bool, retErr error) {
	cmd := exec.CommandContext(s.ctx, s.ffmpegBin, s.buildFFmpegArgs(rtspURL, tagHVC1)...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return false, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return false, fmt.Errorf("start ffmpeg live stream: %w", err)
	}

	// Guard initial RTSP handshake so unreachable cameras fail within 12s rather than hanging forever.
	initTimer := time.AfterFunc(12*time.Second, func() {
		s.mu.Lock()
		hasInit := len(s.initSeg) > 0
		s.mu.Unlock()
		if !hasInit {
			_ = cmd.Process.Kill()
		}
	})
	defer initTimer.Stop()

	var initBuf bytes.Buffer
	var pendingMoof bytes.Buffer
	gotMoov := false

	for {
		box, typ, readErr := readMP4Box(stdout)
		if readErr != nil {
			initTimer.Stop()
			_ = cmd.Wait()
			errText := strings.TrimSpace(s.client.Redact(stderr.String()))
			if !gotMoov && tagHVC1 && strings.Contains(strings.ToLower(errText), "incompatible with output codec") {
				return true, nil
			}
			if !gotMoov {
				if errText != "" {
					return false, fmt.Errorf("RTSP live stream failed: %s", lastLine(errText))
				}
				if s.ctx.Err() != nil {
					return false, s.ctx.Err()
				}
				return false, errors.New("RTSP live stream failed or timed out")
			}
			return false, nil
		}

		if !gotMoov {
			initBuf.Write(box)
			if typ == "moov" {
				gotMoov = true
				initTimer.Stop()
				initBytes := append([]byte(nil), initBuf.Bytes()...)
				mime := ExtractMimeFromMoov(box)
				vidTrack := extractVideoTrackID(box)

				s.mu.Lock()
				s.initSeg = initBytes
				s.mime = mime
				s.videoTrackID = vidTrack
				for sub := range s.subs {
					sub.initSeg = initBytes
					sub.mime = mime
				}
				s.mu.Unlock()

				signalReady(nil)
			}
			continue
		}

		switch typ {
		case "moof", "sidx":
			pendingMoof.Write(box)
		case "mdat":
			pendingMoof.Write(box)
			frag := append([]byte(nil), pendingMoof.Bytes()...)
			pendingMoof.Reset()
			s.broadcastFragment(frag)
		}
	}
}

func (s *streamSession) broadcastFragment(frag []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Inspect first box in frag if it's moof (or after sidx) to see if this fragment starts a new video GOP.
	pos := 0
	isSync := false
	for pos+8 <= len(frag) {
		sz := int(binary.BigEndian.Uint32(frag[pos : pos+4]))
		typ := string(frag[pos+4 : pos+8])
		if sz < 8 || pos+sz > len(frag) {
			break
		}
		if typ == "moof" {
			if moofHasVideoSync(frag[pos:pos+sz], s.videoTrackID) {
				isSync = true
			}
			break
		}
		pos += sz
	}

	if isSync || len(s.gopCache) >= maxGOPCacheFrags || s.gopBytes+len(frag) > maxGOPCacheBytes {
		s.gopCache = s.gopCache[:0]
		s.gopBytes = 0
	}
	s.gopCache = append(s.gopCache, frag)
	s.gopBytes += len(frag)

	for sub := range s.subs {
		select {
		case sub.ch <- frag:
		default:
			// Client fell too far behind (>64 fragments / ~6.4s); drop oldest buffered fragment so live edge recovers.
			select {
			case <-sub.ch:
			default:
			}
			select {
			case sub.ch <- frag:
			default:
			}
		}
	}
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) == 0 {
		return ""
	}
	return strings.TrimSpace(lines[len(lines)-1])
}
