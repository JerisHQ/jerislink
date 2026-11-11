# JerisLink v0.0.7

Release checkpoint: 2026-09-16

## Accepted baseline

- Windows viewer: x64, H.264, 3712x2088 @ 60 fps.
- Video: H.264 4:2:0 Full Range, 25 Mbps.
- ScreenCaptureKit capture queue depth: 2.
- Strict loss recovery with on-demand keyframe request.
- Mouse movement: low-latency UDP side-channel.
- Keyboard, mouse buttons, scroll and clipboard remain on the reliable control path.
- Scroll scale: 1.0.
- Remote cursor is hidden from the captured video; Windows renders the local cursor.
- Cursor shape sync is move-triggered and coalesced; no permanent AppKit polling timer.

## Fixes and improvements

- macOS production naming standardized to `JerisLink Host`, `JerisLink Input Helper`, and `org.jeris.jerislink.*` services.
- Eliminated corrupted dependent frames after UDP video loss by waiting for a valid keyframe.
- Added immediate keyframe requests to reduce strict-recovery stalls.
- Removed the visible mouse-following delay by using the local Windows cursor.
- Added macOS cursor-shape synchronization for text and resize targets.
- Restored Parsec-like scroll speed.
- Fixed ScreenCaptureKit starvation at high resolution by using queueDepth=2; queueDepth=1 is known to stall after the first frame on the current 3712x2088/macOS 27 path.

## Known limitation

- Dragging macOS windows still shows more video-follow latency than Parsec. Input/cursor response is immediate; the remaining gap is in the video capture/encode/display path and is intentionally deferred to post-v0.0.7 work.

## Release artifacts

- `Jerislink-0.0.7-windows-x64-setup.exe`
- `JerisLinkHost-v0.0.7`
- `SHA256SUMS.txt`

Artifacts are stored outside the Git working tree under `~/Documents/Jerislink/releases/v0.0.7/`.
