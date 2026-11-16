# tp-ipc

Local CLI and multi-camera [MCP](https://modelcontextprotocol.io) server for
mainland China **TP-LINK `TL-IPC`** cameras (`TL-IPC48AW`, `TL-IPC48AW-PLUS`,
and compatible `TL-IPC` models). Runs as a single static binary on macOS and
Linux (`arm64` and `x86_64`). MIT licensed.

Mainland China TP-LINK `TL-IPC` cameras run a different local firmware stack
from international Tapo cameras (`pytapo` and Tapo cloud clients cannot talk to
them). `tp-ipc` speaks their native LAN protocols directly—HTTP control, ONVIF
PTZ/events, RTSP live streams, and `MULTITRANS` talkback and SD card
playback—with no `tplinkcloud.com.cn` account or mobile app after first-time
activation.

## Usage

### Discover and add cameras

```sh
$ tp-ipc discover
192.168.1.60      TP-LINK IPC (activated)     model=IPC                  http://192.168.1.60:2020/onvif/device_service
192.168.1.61      TP-LINK IPC (activated)     model=IPC                  http://192.168.1.61:2020/onvif/device_service

$ printf '%s\n' "$CAMERA_PASSWORD" | tp-ipc camera add desk --default --host 192.168.1.60 --user admin --password-stdin
Verified TL-IPC48AW 4.0 (1.0.9 Build 250728 Rel.54812n) as profile "desk". Saved to ~/.config/tp-ipc/config.json (0600)

$ printf '%s\n' "$DOOR_PASSWORD" | tp-ipc camera add door --host 192.168.1.61 --user admin --password-stdin
$ tp-ipc check
Connected: TL-IPC48AW 4.0 (desk) [desk @ 192.168.1.60]
Firmware:  1.0.9 Build 250728 Rel.54812n
RTSP 4K:   rtsp://admin:***@192.168.1.60:554/stream1
RTSP Sub:  rtsp://admin:***@192.168.1.60:554/stream2
```

Pass `-c <camera>` to target any configured profile, and `--json` on any command
for machine-readable output:

```sh
tp-ipc -c door status --json
```

### Snapshots, live clips, and speaker talkback

```sh
tp-ipc snap -o desk.jpg                   # Fast sub-stream JPEG (640x360)
tp-ipc snap --4k -o desk-4k.jpg           # Full 3840x2160 frame
tp-ipc snap --zoom 3 -o zoom.jpg          # 3x digital crop from the 4K stream
tp-ipc record -d 5 --4k -o clip.mkv       # 5s lossless H.265/H.264 clip
tp-ipc play-audio chime.wav               # Stream audio through the camera speaker
```

### Historical SD card video export

Query the on-camera SD card calendar and export any historical time window into
a local `.mp4` or `.mkv` without video re-encoding (preserving 4K H.265/H.264
video and camera microphone audio across segment boundaries):

```sh
$ tp-ipc recordings dates 2026-01
2026-01-14
2026-01-15

$ tp-ipc recordings list 2026-01-15
2026-01-15 11:58:12 -> 2026-01-15 12:04:40  ( 388s, timing)
2026-01-15 12:04:40 -> 2026-01-15 12:12:05  ( 445s, motion)

$ tp-ipc export --date 2026-01-15 --from 12:00 --to 12:10 -o noon.mp4
Exported SD recording (2 segment(s), 600.0s media, 0s gap) to noon.mp4 (78412096 bytes)
```

### Pan/tilt, presets, and device controls

```sh
tp-ipc ptz status
tp-ipc ptz left --step 0.05
tp-ipc ptz goto --pan 0.0 --tilt 0.1
tp-ipc preset save desk-view
tp-ipc preset goto 1

tp-ipc privacy off                        # Physical lens privacy mask
tp-ipc night-vision smart                 # ir | color | smart
tp-ipc detect person on                   # person | motion | tamper
tp-ipc tracking off
tp-ipc led on
tp-ipc volume 70
tp-ipc events --wait 5                    # Poll ONVIF motion/tamper events
```

### Multi-camera MCP server (`stdio`)

One `tp-ipc mcp` process serves all configured cameras over `stdio`, caching
independent login sessions per camera. Add it to Claude Desktop, Claude Code,
Codex, or any MCP client:

```json
{
  "mcpServers": {
    "tp-ipc": {
      "command": "/usr/local/bin/tp-ipc",
      "args": ["mcp"],
      "env": {
        "IPC_CAMERA": "desk",
        "IPC_HOST_DESK": "192.168.1.60",
        "IPC_PASSWORD_DESK": "your-desk-camera-password",
        "IPC_HOST_DOOR": "192.168.1.61",
        "IPC_PASSWORD_DOOR": "your-door-camera-password",
        "IPC_MEDIA_DIR": "/tmp/ipc-media",
        "IPC_AUDIO_DIR": "/tmp/ipc-audio"
      }
    }
  }
}
```

If you already saved profiles with `tp-ipc camera add`, `env` only needs
`IPC_MEDIA_DIR` (for `camera_record_clip` and `camera_download_recording`) and
`IPC_AUDIO_DIR` (for `camera_play_audio`).

## Install

**Prebuilt static binary** (macOS & Linux, `arm64` & `amd64`):

```sh
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m); [ "$ARCH" = "x86_64" ] && ARCH=amd64; [ "$ARCH" = "aarch64" ] && ARCH=arm64
curl -fsSL "https://github.com/aur3l14no/tp-ipc-cli/releases/latest/download/tp-ipc-${OS}-${ARCH}" -o tp-ipc
chmod +x tp-ipc && sudo mv tp-ipc /usr/local/bin/
```

**With Go 1.22+**:

```sh
CGO_ENABLED=0 go install github.com/aur3l14no/tp-ipc-cli/cmd/tp-ipc@latest
```

**Runtime dependency**: `ffmpeg` on `PATH` is required only for media commands
(`snap`, `record`, `export` / `recordings download`, and `play-audio`, plus
their MCP equivalents). Discovery, status, PTZ, presets, detectors, alarms,
events, and SD recording index queries require no external tools.

## Configuration

Profiles added via `tp-ipc camera add` or `tp-ipc configure` are stored in
`$XDG_CONFIG_HOME/tp-ipc/config.json` (default `~/.config/tp-ipc/config.json`)
with `0600` permissions; `tp-ipc` refuses to load a config file readable by
group or others on Unix.

For stateless containers, CI, or secret managers, configure cameras via
environment variables or global flags instead of writing a config file:

| Source | Variables / Flags | Purpose |
| --- | --- | --- |
| Global flags | `-c`/`--camera`, `-H`/`--host`, `-u`/`--user`, `--password-stdin`, `--password-file`, `--http-port`, `--rtsp-port`, `--onvif-port`, `--json` | Per-invocation target, port overrides (defaults `80` / `554` / `2020`), and JSON output |
| Indexed multi-camera env | `IPC_HOST_<NAME>`, `IPC_USER_<NAME>`, `IPC_PASSWORD_<NAME>`, `IPC_PASSWORD_FILE_<NAME>`, `IPC_HTTP_PORT_<NAME>`, `IPC_RTSP_PORT_<NAME>`, `IPC_ONVIF_PORT_<NAME>` | Define or override named camera `<name>` (case-insensitive, `-`/`.` mapped to `_`) |
| JSON multi-camera env | `IPC_CAMERAS` | JSON map of profiles, e.g. `{"desk":{"host":"192.168.1.60"}}` |
| Default / single camera env | `IPC_CAMERA`, `IPC_HOST`, `IPC_USER`, `IPC_PASSWORD`, `IPC_PASSWORD_FILE` | Select default profile (`IPC_CAMERA`) or configure a single unnamed camera |
| Media directories | `IPC_MEDIA_DIR`, `IPC_AUDIO_DIR` | Output directory for recorded/exported clips and input directory for `camera_play_audio` |

## Reference

### CLI commands

| Command | Summary |
| --- | --- |
| `discover [--timeout 2] [--cidr 192.168.1.0/24]` | Discover cameras on L2 LAN (WS-Discovery) or across a routed `/22`–`/32` IPv4 subnet |
| `camera <list\|add\|use\|remove>` | List profiles, add/verify a named profile (`--default`), switch default, or delete |
| `configure [-c <name>]` | Verify login and save camera (defaults profile name to the camera's alias) |
| `activation` | Probe first-time activation state without logging in |
| `check` | Verify login and print model, firmware, RTSP URLs, and ONVIF endpoint |
| `info` | Read model, hardware/firmware version, MAC address, and local capability flags |
| `status` | Read detectors, privacy mask, night vision, tracking, LED, speaker volume, and SD card space |
| `snap [-o out.jpg] [--hq\|--4k] [--zoom 1..5] [--focus-x 0.5] [--focus-y 0.5]` | Capture a JPEG frame (`-o -` writes raw JPEG bytes to stdout) |
| `record [-d 5] [--hq\|--4k] [-o clip.mkv]` | Record a `1`–`300`s live RTSP clip without video transcoding (`.mkv` or `.mp4`) |
| `export --from <start> --to <end> [--date YYYY-MM-DD] [-o out.mp4]` | Export historical SD card video + audio across a time range (`HH:MM`, `HH:MM:SS`, datetime, or RFC3339) |
| `recordings <dates [YYYY-MM] \| list [YYYY-MM-DD] \| download ...>` | List months' active recording dates, inspect daily segments, or download a range |
| `play-audio <file>` | Stream a local audio file through the camera speaker over RTSP `MULTITRANS` |
| `ptz <status\|left\|right\|up\|down\|move\|goto\|stop>` | Read pan/tilt coordinates in `[-1, 1]`, nudge (`--step 0.01..0.25`), move, or stop |
| `preset <list\|save\|goto\|remove>` | List, save, jump to, or delete on-camera PTZ presets |
| `privacy <on\|off>` | Toggle physical lens privacy mask |
| `night-vision <ir\|color\|smart>` | Switch infrared, full-color white-light, or smart motion-color night vision |
| `detect <person\|motion\|tamper> <on\|off>` | Toggle on-device detection modules |
| `tracking <on\|off>` | Toggle automatic pan/tilt subject tracking |
| `led <on\|off>` | Toggle status LED |
| `volume <0-100>` | Set camera speaker volume |
| `alarm <start [1-5] \| stop>` | Sound manual alarm for `1`–`5` seconds (auto-stops) or stop immediately |
| `events [--wait 1..15]` | Poll ONVIF PullPoint motion and tamper notifications |
| `watch-person [--wait 1..30]` | Wait silently for person-detection white-light linkage and restore prior settings |
| `raw '<json>'` | Execute a raw `/stok=<token>/ds` JSON payload |
| `mcp` | Run the MCP JSON-RPC 2.0 server over `stdio` |

### MCP tools (29)

`camera_list` and `camera_discover` operate globally; all other 27 tools accept
an optional `"camera": "<profile-name>"` property and use the default camera
when omitted.

| Category | Tools |
| --- | --- |
| Discovery & inventory | `camera_list`, `camera_discover` |
| Inspection | `camera_activation_status`, `camera_info`, `camera_status` |
| Live media & talkback | `camera_snapshot`, `camera_record_clip`, `camera_play_audio` |
| SD card playback | `camera_recording_dates`, `camera_recordings`, `camera_download_recording` |
| Pan/tilt & presets | `camera_ptz_status`, `camera_move`, `camera_go_to_position`, `camera_ptz_stop`, `camera_presets`, `camera_save_preset`, `camera_go_to_preset`, `camera_remove_preset` |
| Controls & alarms | `camera_set_privacy`, `camera_set_led`, `camera_set_speaker_volume`, `camera_set_tracking`, `camera_set_detection`, `camera_set_night_vision`, `camera_alarm`, `camera_stop_alarm` |
| Events | `camera_events`, `camera_person_alarm` |

## Tested Hardware

| Model | Hardware | Firmware | Login Handshake |
| --- | --- | --- | --- |
| `TL-IPC48AW-PLUS` | `5.0` | `1.0.3 Build 260119 Rel.38255n` | RSA PKCS#1 v1.5 (`encrypt_type: "2"`) |
| `TL-IPC48AW-PLUS` | `2.0` | `1.0.4 Build 240702 Rel.67033n` | MD5 challenge-response (`md5_encrypt_type: 1`) |

Other mainland China `TL-IPC` models and hardware revisions sharing the `/stok=<token>/ds`, ONVIF `:2020`, and RTSP/`MULTITRANS` `:554` stack should also work.

## Caveats

- **First-time activation.** Set the camera's initial admin password once via
  its built-in web UI (`http://<camera-ip>/`) or the TP-LINK app before using
  `tp-ipc`.
- **One SD playback stream per camera.** Firmware serves a single SD card
  playback session at a time; run `export` jobs sequentially per camera.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for building from source, running tests,
cross-compiling release binaries, and mainland `TL-IPC` protocol notes.

## Disclaimer

`tp-ipc` is an independent open-source interoperability tool and is not
affiliated with, endorsed by, or sponsored by TP-LINK. Use it only on cameras
and networks you own or have explicit authorization to manage.

## License

[MIT](LICENSE).
