# Contributing & Development

`tp-ipc` is a pure-Go (`CGO_ENABLED=0`) project using only the Go standard
library.

## Prerequisites

- Go 1.22 or later
- `ffmpeg` on `PATH` (optional for unit tests; needed for live snapshot, clip,
  SD playback export, and speaker talkback integration checks)

## Build & Test

```sh
make build            # Build native static binary ./tp-ipc
make test             # Run all unit tests with CGO_ENABLED=0
go vet ./...          # Static analysis
make dist             # Cross-compile darwin/{arm64,amd64} & linux/{arm64,amd64} into ./dist/
```

## Layout

| Path | Responsibility |
| --- | --- |
| `cmd/tp-ipc/main.go` | CLI flag parsing, subcommand dispatch, human & `--json` output |
| `internal/config/` | Multi-camera store (`~/.config/tp-ipc/config.json`, `0600`), environment variable overlays, profile and proxy validation |
| `internal/ipc/auth.go` | Unauthenticated `/pc/Content.htm` activation probe and RSA PKCS#1 v1.5 `/ds` challenge-response cipher |
| `internal/ipc/client.go` | Session lifecycle, `stok` token renewal, credential redaction |
| `internal/ipc/proxy.go` | Shared OpenSSH `-D` dynamic tunnel pool, SOCKS5 / HTTP CONNECT dialers, and local RTSP loopback bridge |
| `internal/ipc/device.go` | `/stok=<token>/ds` JSON API wrappers (status, detectors, night vision, LED, speaker, presets, SD index) |
| `internal/ipc/discover.go` | ONVIF WS-Discovery UDP multicast (`239.255.255.250:3702`) and `/22`–`/32` HTTP CIDR scan |
| `internal/ipc/onvif.go` | ONVIF Profile S/T WS-Security `PasswordDigest` PTZ control and PullPoint event subscriptions |
| `internal/ipc/media.go` | RTSP single-frame JPEG capture (`stream1`/`stream2` + digital crop), lossless clip muxing, `MULTITRANS` G.711 A-law speaker talkback |
| `internal/ipc/playback.go` | Historical SD card time-range export over RTSP `MULTITRANS` (`playback`) + RTP-over-TCP demuxing into lossless `.mp4`/`.mkv` |
| `internal/live/` | Local authenticated web live console (fMP4 MSE stream hub, PTZ/preset/device controls) and native RTSP player launcher |

## Mainland `TL-IPC` Protocol Notes

Mainland China TP-LINK `TL-IPC` firmware differs from international Tapo
firmware in several subtle ways that the codebase handles directly:

- **RSA & MD5 challenge-response (`internal/ipc/auth.go`, `internal/ipc/client.go`).**
  The unauthenticated `/pc/Content.htm` challenge returns an URL-encoded base64
  DER `SubjectPublicKeyInfo` whose modulus may omit the leading `0x00` sign byte
  required by strict ASN.1 DER parsers; `ParseCameraRSAPublicKey` reconstructs
  the modulus and exponent without failing on non-canonical integer padding and
  encrypts `<securityEncode(pw)>:<nonce>` via PKCS#1 v1.5 (`encrypt_type: "2"`).
  Earlier hardware revisions (such as `TL-IPC48AW-PLUS 2.0` vs `5.0`)
  additionally advertise `"md5_encrypt_type": 1` in the challenge JSON,
  requiring `password` to be `md5("<raw_pw>:<nonce>")` alongside
  `"md5_encrypt_type": "1"` in the login payload instead of the RSA ciphertext.
- **Session concurrency (`internal/ipc/client.go`).** Login serialization uses a
  dedicated `loginMu` separate from `stateMu` so transport error redaction never
  re-enters a held mutex.
- **ONVIF + `/ds` fallback (`internal/ipc/onvif.go`).** Pan/tilt queries and
  moves prefer ONVIF port `2020` (`WS-Security` `PasswordDigest`) and fall back
  to `/stok=<token>/ds` motor calls when port `2020` is filtered. PullPoint
  `PullMessages` long-polls use a dedicated HTTP client whose timeout exceeds
  the requested wait window. Hardware revisions whose ONVIF pan or tilt axis is
  reversed (e.g., `TL-IPC48AW-PLUS 2.0`) can set per-camera `invert_pan` /
  `invert_tilt` in `config.json`, via `--invert-pan` / `--invert-tilt`, or in
  the `tp-ipc live` PTZ panel.
- **Live fMP4 MSE streaming (`internal/live/fmp4.go`, `internal/live/ui.html`).**
  Some `TL-IPC` H.264 substreams emit trailing `00 00 01 00` Annex-B bytes that
  FFmpeg's MP4 muxer turns into 0-length AVCC NAL units (`00 00 00 00`), which
  Chromium MSE rejects (`Failed to prepare video sample for decode`). Live
  H.264 passthrough strips type-0 NALs via `-bsf:v filter_units=remove_types=0`
  and normalizes RTSP audio timestamps via `aresample=async=1:first_pts=0`,
  while the web console handles `<video>` decode errors by falling back to
  H.264 transcoding.
- **Historical SD export (`internal/ipc/playback.go`).** The camera streams
  historical recordings over RTSP `MULTITRANS` on port `554`: JSON control
  frames (`type: "request"` / `"notification"`) and interleaved RTP video/audio
  packets share one TCP connection. Firmware reports `G711A`/`G711U` in the
  `replay` notification, which must be mapped to IANA SDP names `PCMA`/`PCMU`
  (`8000 Hz`) so `ffmpeg` decodes the microphone track alongside lossless H.265
  or H.264 video (`-c:v copy`).

## Releasing

1. Update `version` in `cmd/tp-ipc/main.go` and `VERSION` in `Makefile`.
2. Run `go vet ./... && make test && make VERSION=<x.y.z> dist`.
3. Commit, tag `v<x.y.z>`, push to `main`, and publish a GitHub Release with the
   files in `dist/` (`tp-ipc-darwin-arm64`, `tp-ipc-darwin-amd64`,
   `tp-ipc-linux-arm64`, `tp-ipc-linux-amd64`, and `SHA256SUMS`).
