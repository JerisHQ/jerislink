JerisLink - Windows x64 (version: see VERSION, or the file properties of Jerislink.exe)

Purpose
-------
Low-latency Jerislink remote viewer over the existing Tailscale path.

v0.0.9.5 hotfix
-----------------

- Restores normal held-key autorepeat for ordinary keys such as Space, Backspace
  and arrow/navigation keys while preserving JerisLink shortcut remapping.
- Windows Viewer only; no transport/protocol change and fully compatible with the
  v0.0.9.4 macOS Host / Input Helper production baseline.

v0.0.9.5 defaults
---------------
Remote host: saved in Settings (first start asks), or --source-ip / JERISLINK_SOURCE_IP
Video UDP:   38402
Control TCP: 38400
Mouse UDP:   38412
Video:       auto-native host framebuffer @ 60 fps, H.264 / 25 Mbps
Recovery:    strict, on-demand keyframe request
Mouse move:  UDP side-channel; buttons/keyboard/scroll remain reliable control
Scroll:      scale 1.0

Viewer status and settings
--------------------------
The title bar shows the effective negotiated video mode, for example:
JerisLink — HEVC · 18 Mbps

Use the visible menu bar:
- Settings > Connection Settings...
- Connection > Connection Info...

Connection Info shows configured versus effective codec/bandwidth, remote
resolution/FPS, startup control RTT, active decoder/backend, and GPU adapter.
The legacy Viewer system-menu "Video Settings..." entry is retained for
compatibility in v0.0.9.5.

Codec:
- H.264 (stable default)
- HEVC / H.265
- Auto (prefers HEVC when the Windows client exposes a D3D11-aware HEVC decoder)

Bitrate:
- 0 = Auto (25 Mbps for H.264, 18 Mbps for HEVC)
- Manual range = 4-100 Mbps

Saved settings are stored per Windows user and apply on the next Jerislink
connection. If HEVC is unavailable or its hardware presentation path fails,
Jerislink requests H.264 from the Host instead of leaving a black session.

The Host also returns its current native framebuffer width/height during video
negotiation. Unless --width/--height are explicitly supplied, the Viewer uses
that negotiated size as the Media Foundation decoder's startup geometry.

The Viewer follows the encoded stream/SPS resolution; it does not require a
hard-coded startup resolution to match the Mac display.

Startup
-------
Double-click Jerislink.exe. No command line is needed.

First start: a JerisLink Settings window opens. Enter the Mac host's
Tailscale IPv4 address, pick the codec and bitrate, and press Connect.
The settings are saved for this Windows user and used on every later start.

Change settings later:
- hold Shift while starting Jerislink.exe, or
- in the running viewer: Settings > Connection Settings... (applies on the next start), or
- start it once with: Jerislink.exe --settings

"This PC's address" can stay empty: Jerislink then uses this PC's active
Tailscale IPv4 address (100.64.0.0/10). Fill it in only to force one address.

Saved values (HKCU\Software\Jeris\Jerislink): HostIp, BindIp, VideoCodec,
VideoBitrateMbps. Priority per value: command line > saved setting >
JERISLINK_SOURCE_IP (host only) / automatic Tailscale address (this PC only).

Check what a start would use, without connecting:
  Jerislink.exe --print-config %TEMP%\jerislink-config.txt

Advanced command line overrides
-------------------------------
Jerislink.exe --bind-ip <local-tailscale-ipv4> --source-ip <mac-tailscale-ipv4>
Jerislink.exe --codec h264 --bitrate-mbps 25
Jerislink.exe --codec hevc --bitrate-mbps 18
Jerislink.exe --codec auto --bitrate-mbps 0

Logs
----
%TEMP%\jerislink-viewer.log
%TEMP%\jerislink-viewer-history.log

Status
------
Pre-1.0 private build. MR02 transport remains frozen for regression compatibility.
