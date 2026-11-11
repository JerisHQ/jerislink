# Jerislink

JerisLink is a Tailscale-first remote desktop client/host developed for low-latency access between a Windows client and a macOS host.

## Current production baseline

- Version: v0.0.8
- Windows client: Media Foundation H.264 decode with D3D11 video-processor presentation and automatic stream-resolution changes
- macOS host: ScreenCaptureKit + VideoToolbox H.264, auto-native active-display framebuffer resolution
- Control: keyboard and mouse over the Jerislink/MRC control channel
- Clipboard: bidirectional Unicode/plain-text sync over a dedicated second MRC TCP session, with loop prevention
- Keyboard compatibility: Windows editing shortcuts, Win+Space input-source switching, Caps Lock / Chinese-English workflow
- Network: your own Tailscale tailnet (direct peer path preferred)

## v0.0.9 development status

The feature/v0.0.9-video-settings branch adds the first client-controlled
video-settings phase without changing the deployed v0.0.8 production baseline:

- Viewer Video Settings UI for Auto / H.264 / HEVC (H.265).
- Per-user saved bitrate: 0 = Auto, manual 4-100 Mbps.
- MRC1 codec/bitrate negotiation over the existing control connection.
- H.264 remains the safe default at 25 Mbps.
- Auto prefers HEVC when the Windows client exposes a D3D11-aware HEVC decoder;
  Auto bitrate is 18 Mbps for HEVC and 25 Mbps for H.264.
- Unsupported HEVC falls back to H.264 rather than leaving a black session.
- Human A/B validation on a Windows AMD laptop showed HEVC/18 and H.264/25 with no perceptible
  interaction-latency difference while the Tailscale peer path was direct.

## v0.0.9.1 production hotfix

Production deployment testing found that a normal Windows launch still carried
the legacy nominal decoder size 3712x2088. H.264 corrected itself from SPS, but
HEVC could initialize Media Foundation with that stale size and then stall
before first presentation when the Host was actually streaming 3776x2124.

v0.0.9.1 extends VIDEO_CONFIG_ACK with the Host's current framebuffer width
and height. A client without an explicit --width/--height override uses the
negotiated framebuffer size to initialize the decoder. Older 6-byte ACKs remain
accepted; HEVC safely falls back to H.264 if an older Host cannot provide a
remote size.

Binary installers and release packages are intentionally kept out of Git history. They are archived separately under the Jerislink release directory.
