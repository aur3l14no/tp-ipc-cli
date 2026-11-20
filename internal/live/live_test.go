package live

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aur3l14no/tp-ipc-cli/internal/config"
	"github.com/aur3l14no/tp-ipc-cli/internal/ipc"
)

func makeMP4Box(typ string, payload []byte) []byte {
	buf := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(buf)))
	copy(buf[4:8], typ)
	copy(buf[8:], payload)
	return buf
}

func buildSyntheticMoov(videoFourCC string, includeAudio bool) []byte {
	// tkhd v0: version/flags(4) + ctime(4) + mtime(4) + track_ID(4) + reserved(4) + duration(4)
	tkhdVid := make([]byte, 24)
	binary.BigEndian.PutUint32(tkhdVid[12:16], 1)

	hdlrVid := make([]byte, 16)
	copy(hdlrVid[8:12], "vide")

	var codecCfg []byte
	if videoFourCC == "hvc1" {
		// hvcC: ver=1, profile=1 (Main), compat=0x60000000 (-> 6), constraints=00..00, level=150 (L150)
		hvcC := []byte{
			0x01, 0x01,
			0x60, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x96,
		}
		codecCfg = makeMP4Box("hvcC", hvcC)
	} else {
		avcC := []byte{0x01, 0x64, 0x00, 0x1F, 0xFF}
		codecCfg = makeMP4Box("avcC", avcC)
	}

	visSampleEntry := append(make([]byte, 78), codecCfg...)
	stsdPayload := make([]byte, 8)
	binary.BigEndian.PutUint32(stsdPayload[4:8], 1)
	stsdPayload = append(stsdPayload, makeMP4Box(videoFourCC, visSampleEntry)...)

	stbl := makeMP4Box("stbl", makeMP4Box("stsd", stsdPayload))
	minf := makeMP4Box("minf", stbl)
	mdia := makeMP4Box("mdia", append(makeMP4Box("hdlr", hdlrVid), minf...))
	vidTrak := makeMP4Box("trak", append(makeMP4Box("tkhd", tkhdVid), mdia...))

	moovBody := vidTrak
	if includeAudio {
		tkhdAud := make([]byte, 24)
		binary.BigEndian.PutUint32(tkhdAud[12:16], 2)
		hdlrAud := make([]byte, 16)
		copy(hdlrAud[8:12], "soun")
		audEntry := make([]byte, 28)
		audStsd := make([]byte, 8)
		binary.BigEndian.PutUint32(audStsd[4:8], 1)
		audStsd = append(audStsd, makeMP4Box("mp4a", audEntry)...)
		audTrak := makeMP4Box("trak", append(
			makeMP4Box("tkhd", tkhdAud),
			makeMP4Box("mdia", append(makeMP4Box("hdlr", hdlrAud), makeMP4Box("minf", makeMP4Box("stbl", makeMP4Box("stsd", audStsd)))...))...,
		))
		moovBody = append(moovBody, audTrak...)
	}

	return makeMP4Box("moov", moovBody)
}

func buildSyntheticMoof(trackID uint32, syncSample bool) []byte {
	tfhd := make([]byte, 8)
	binary.BigEndian.PutUint32(tfhd[4:8], trackID)

	// trun with first_sample_flags_present (0x000004)
	trun := make([]byte, 12)
	binary.BigEndian.PutUint32(trun[0:4], 0x000004)
	binary.BigEndian.PutUint32(trun[4:8], 1)
	if syncSample {
		binary.BigEndian.PutUint32(trun[8:12], 0x02000000) // sample_depends_on=2, non_sync=0
	} else {
		binary.BigEndian.PutUint32(trun[8:12], 0x01010000) // sample_depends_on=1, non_sync=1
	}

	traf := makeMP4Box("traf", append(makeMP4Box("tfhd", tfhd), makeMP4Box("trun", trun)...))
	return makeMP4Box("moof", traf)
}

func TestExtractMimeAndSyncDetection(t *testing.T) {
	hevcMoov := buildSyntheticMoov("hvc1", true)
	gotHEVC := ExtractMimeFromMoov(hevcMoov)
	if gotHEVC != `video/mp4; codecs="hvc1.1.6.L150.0, mp4a.40.2"` {
		t.Fatalf("unexpected HEVC+AAC mime: %s", gotHEVC)
	}
	if id := extractVideoTrackID(hevcMoov); id != 1 {
		t.Fatalf("expected video track ID 1, got %d", id)
	}

	avcVideoOnly := buildSyntheticMoov("avc1", false)
	gotAVC := ExtractMimeFromMoov(avcVideoOnly)
	if gotAVC != `video/mp4; codecs="avc1.64001F"` {
		t.Fatalf("unexpected H.264 video-only mime: %s", gotAVC)
	}

	syncMoof := buildSyntheticMoof(1, true)
	nonSyncMoof := buildSyntheticMoof(1, false)
	audioMoof := buildSyntheticMoof(2, true)
	if !moofHasVideoSync(syncMoof, 1) {
		t.Fatal("expected syncMoof to be detected as video sync")
	}
	if moofHasVideoSync(nonSyncMoof, 1) {
		t.Fatal("expected nonSyncMoof NOT to be detected as video sync")
	}
	if moofHasVideoSync(audioMoof, 1) {
		t.Fatal("expected audioMoof NOT to be detected as video sync")
	}
}

func TestServerSecurityAndStreamHVC1Fallback(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	// Build a binary stream file that our fake ffmpeg emits when -tag:v hvc1 is NOT passed
	var fmp4Stream bytes.Buffer
	fmp4Stream.Write(makeMP4Box("ftyp", []byte("isom0000isommp41")))
	fmp4Stream.Write(buildSyntheticMoov("avc1", true))
	fmp4Stream.Write(buildSyntheticMoof(1, true))
	fmp4Stream.Write(makeMP4Box("mdat", []byte("KEYFRAME_PAYLOAD")))
	fmp4Stream.Write(buildSyntheticMoof(1, false))
	fmp4Stream.Write(makeMP4Box("mdat", []byte("PFRAME_PAYLOAD")))

	streamFixture := filepath.Join(tmp, "fixture.fmp4")
	if err := os.WriteFile(streamFixture, fmp4Stream.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	fakeFFmpeg := filepath.Join(tmp, "ffmpeg")
	script := `#!/bin/sh
for arg in "$@"; do
  if [ "$arg" = "hvc1" ]; then
    echo "[mp4 @ 0x0] Tag hvc1 incompatible with output codec id '27' (avc1)" >&2
    exit 183
  fi
done
cat "` + streamFixture + `"
sleep 1
`
	if err := os.WriteFile(fakeFFmpeg, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	// Mock camera HTTP server
	camSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/pc/Content.htm" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error_code": -40401,
				"data": map[string]any{
					"code":             -40407,
					"nonce":            "nonce123",
					"md5_encrypt_type": 1,
				},
			})
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["method"] == "do" {
			if _, ok := body["login"]; ok {
				_ = json.NewEncoder(w).Encode(map[string]any{"error_code": 0, "stok": "tok123", "user_group": "root"})
				return
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error_code": 0,
			"device_info": map[string]any{
				"basic_info": map[string]any{
					"device_model": "TL-IPC48AW-PLUS",
					"hw_version":   "2.0",
					"sw_version":   "1.0.4",
				},
			},
			"lens_mask": map[string]any{
				"lens_mask_info": map[string]any{"enabled": "off"},
			},
			"image": map[string]any{
				"switch": map[string]any{"night_vision_mode": "inf_night_vision"},
			},
		})
	}))
	defer camSrv.Close()

	_, camHost, camPort, _ := config.ParseHostInput(camSrv.URL)
	if _, err := config.Save(config.Settings{
		Name:     "dogee",
		Scheme:   "http",
		Host:     camHost,
		HTTPPort: camPort,
		RTSPPort: 18554,
		User:     "admin",
		Password: "top_secret_cam_pw",
	}, true); err != nil {
		t.Fatal(err)
	}

	if _, err := NewServer(Options{
		Overrides: config.Overrides{Camera: "nonexistent"},
	}); err == nil {
		t.Fatal("expected NewServer to reject unknown explicit camera profile")
	}

	srv, err := NewServer(Options{
		ListenAddr: "127.0.0.1:0",
		Token:      "fixed_test_token_123456",
		FFmpegBin:  fakeFFmpeg,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	baseURL, authURL, _, err := srv.Start(ctx)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// 1. Unauthenticated API call must be rejected with 401
	resp1, err := http.Get(baseURL + "/api/bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", resp1.StatusCode)
	}

	// 2. Token URL sets HttpOnly cookie and redirects 303 to clean /
	noRedirectClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp2, err := noRedirectClient.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusSeeOther || resp2.Header.Get("Location") != "/" {
		t.Fatalf("expected 303 redirect to /, got %d Location=%q", resp2.StatusCode, resp2.Header.Get("Location"))
	}
	cookies := resp2.Cookies()
	if len(cookies) == 0 || cookies[0].Name != sessionCookieName || !cookies[0].HttpOnly {
		t.Fatalf("expected HttpOnly session cookie, got %+v", cookies)
	}

	// 3. Cookie-authenticated POST without X-Requested-With must be rejected (CSRF defense)
	reqCSRF, _ := http.NewRequest(http.MethodPost, baseURL+"/api/control", strings.NewReader(`{"target":"led","enabled":true}`))
	reqCSRF.AddCookie(cookies[0])
	respCSRF, err := http.DefaultClient.Do(reqCSRF)
	if err != nil {
		t.Fatal(err)
	}
	respCSRF.Body.Close()
	if respCSRF.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 CSRF block without X-Requested-With, got %d", respCSRF.StatusCode)
	}

	// 4. Cookie-authenticated POST WITH X-Requested-With succeeds
	reqOK, _ := http.NewRequest(http.MethodPost, baseURL+"/api/control", strings.NewReader(`{"target":"led","enabled":true}`))
	reqOK.AddCookie(cookies[0])
	reqOK.Header.Set("X-Requested-With", "tp-ipc")
	respOK, err := http.DefaultClient.Do(reqOK)
	if err != nil {
		t.Fatal(err)
	}
	respOK.Body.Close()
	if respOK.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with X-Requested-With, got %d", respOK.StatusCode)
	}

	// 5. /api/stream transparently retries without -tag:v hvc1 on H.264 stream and delivers fMP4 + X-Stream-Mime
	streamCtx, streamCancel := context.WithTimeout(ctx, 3*time.Second)
	defer streamCancel()
	reqStream, _ := http.NewRequestWithContext(streamCtx, http.MethodGet, baseURL+"/api/stream?camera=dogee&quality=sub&codec=copy", nil)
	reqStream.AddCookie(cookies[0])
	respStream, err := http.DefaultClient.Do(reqStream)
	if err != nil {
		t.Fatalf("stream request failed: %v", err)
	}
	defer respStream.Body.Close()
	if respStream.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(respStream.Body)
		t.Fatalf("expected 200 from /api/stream, got %d: %s", respStream.StatusCode, string(body))
	}
	if mime := respStream.Header.Get("X-Stream-Mime"); mime != `video/mp4; codecs="avc1.64001F, mp4a.40.2"` {
		t.Fatalf("unexpected X-Stream-Mime: %q", mime)
	}

	gotBytes := make([]byte, fmp4Stream.Len())
	if _, err := io.ReadFull(respStream.Body, gotBytes); err != nil {
		t.Fatalf("failed reading expected fMP4 bytes: %v", err)
	}
	if !bytes.Contains(gotBytes, []byte("KEYFRAME_PAYLOAD")) || !bytes.Contains(gotBytes, []byte("PFRAME_PAYLOAD")) {
		t.Fatal("missing expected fMP4 fragment payloads")
	}
}

func TestLaunchPlayerRedactsPasswordOnError(t *testing.T) {
	tmp := t.TempDir()
	fakePlayer := filepath.Join(tmp, "ffplay")
	script := "#!/bin/sh\necho \"error opening $*\" >&2\nexit 1\n"
	if err := os.WriteFile(fakePlayer, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	c, err := ipc.NewClient(config.Settings{
		Name:     "desk",
		Scheme:   "http",
		Host:     "127.0.0.1",
		RTSPPort: 554,
		User:     "admin",
		Password: "ultra_secret_rtsp_pass_99",
	})
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	err = LaunchPlayer(context.Background(), c, true, fakePlayer, &out)
	if err == nil {
		t.Fatal("expected LaunchPlayer error")
	}
	if strings.Contains(err.Error(), "ultra_secret_rtsp_pass_99") || strings.Contains(out.String(), "ultra_secret_rtsp_pass_99") {
		t.Fatalf("password leaked in error=%q or stdout=%q", err.Error(), out.String())
	}
}
