# JerisLink macOS production deployment

Deployment components for JerisLink v0.0.9.4:

- `JerisLink Host.app` — ScreenCaptureKit + VideoToolbox host.
- `JerisLink Input Helper.app` — local input injection helper.
- `JerisLinkHost --control-only` — localhost control service.
- `org.jeris.jerislink.*` LaunchAgents — control, input-helper watchdog and video watchdog.

## Production paths

- Apps: `~/Applications/JerisLink Host.app` and `~/Applications/JerisLink Input Helper.app`
- Support: `~/Library/Application Support/JerisLink/`
- LaunchAgents: `~/Library/LaunchAgents/org.jeris.jerislink.*.plist`

## v0.0.9.4 host baseline

- active main display native framebuffer resolution @ 60 fps (auto-detected; current BetterDisplay mode is 3776x2124)
- paired `--width` / `--height` remain available as explicit debug overrides
- display mode changes are detected at runtime and restart capture/encoder at the new native framebuffer size
- H.264 or HEVC, 4:2:0 Full Range
- H.264 / 25 Mbps remains the stable default
- client-selected codec/bitrate are persisted in `~/Library/Application Support/JerisLink/video-settings.plist`
- the localhost control service accepts MRC1 video configuration requests, returns the current native framebuffer size, and restarts the video Host only when the effective codec/bitrate changes
- the video watchdog reads the persisted codec/bitrate each time it launches the video Host
- keyframe interval 60 with on-demand IDR recovery for both H.264 and HEVC
- Host and Input Helper production builds use the stable `JerisLink Local Code Signing` identity so future rebuilds retain the same macOS TCC code identity
- macOS TCP control/helper sockets suppress SIGPIPE so normal peer disconnects become recoverable send errors instead of terminating a JerisLink service
- ScreenCaptureKit queue depth 2
- video UDP 38402
- control endpoint 38400 (Tailscale proxy) -> localhost 38411
- input helper localhost 38410
- mouse/cursor-state UDP side-channel 38412
- captured macOS cursor hidden; Windows renders the local cursor

The Windows viewer does not require a matching hard-coded startup resolution. v0.0.9.4 negotiates the Host's current framebuffer size together with H.264/HEVC and bitrate before opening the video decoder, then Media Foundation follows encoded stream resolution changes at runtime. HEVC failure is designed to fall back to H.264.

v0.0.9.4 carries forward the v0.0.9.1 remote-size negotiation fix, HEVC on-demand forced-keyframe recovery, stable local macOS code-signing identity, and macOS `SO_NOSIGPIPE` hardening from the v0.0.9.2/v0.0.9.3 production line. The Windows Viewer adds UX-only status improvements: the title bar exposes the effective negotiated codec/bitrate, a visible Settings menu opens Video Settings, and Connection Info shows configured versus effective video state plus decoder/GPU details. The video transport and recovery protocol are unchanged from the verified v0.0.9.3 baseline. The first migration from older ad-hoc-signed production apps still requires one-time Screen Recording and Device Control/Data Access approval.

## Build

Set up the stable local signing identity once on the JerisLink Mac, then build:

```sh
cd mac-host
./Deploy/setup-local-signing.sh
./Deploy/build-apps.sh
```

See `Deploy/SIGNING.md` for the TCC identity model, migration notes, and recovery considerations.

## Install / refresh production services

```sh
cd mac-host
./Deploy/install-production.sh
```

A fresh Mac may require one-time Screen Recording and Accessibility approval from macOS Privacy & Security settings.
