# JerisLink Windows host (H1, dev only)

Phase H1 of the Windows host design (2026-11-27): capture the screen, encode
H.264 with the Media Foundation software encoder and send it as MR02 to one
viewer, so the existing JerisLink viewer shows the picture.

Not in H1: input, audio, clipboard, files, NACK/retransmit, ABR, HEVC,
hardware encoders, connection password, service/installer. The viewer's
requests for those are refused or ignored the way an older macOS host would.

## Dev mode only

There is no connection password yet. The host refuses to start unless it is
told all three:

```
JerisLinkHost.exe --dev-no-password --bind <this PC's tailnet IPv4> --allow <viewer IPv4>
                  [--fps 30] [--bitrate 25] [--max-size 1920x1080]
                  [--capture auto|dda|gdi] [--log host.log] [--seconds N]
                  [--snapshot frame.bmp]
JerisLinkHost.exe --probe [--capture auto|dda|gdi] [--snapshot frame.bmp]
```

- `--bind` must be one specific address (not `0.0.0.0`); control and MRM1
  listen only there.
- `--allow` is the one viewer address; anything else is dropped.
- `--probe` captures one frame, encodes ten and exits: a quick check that
  capture and the encoder work on this machine.
- `--snapshot` writes the captured frame as BMP (after 10 s of streaming,
  or at once with `--probe`).

Builds are unsigned (design doc D14).

## Ports (same as the macOS host)

| Port | Proto | Use |
| --- | --- | --- |
| 38400 | TCP on `--bind` | MRC1 control: transition probe, ping, video config |
| 38412 | UDP on `--bind` | MRM1: keyframe request, ping |
| 38402 | UDP to the viewer | MR02 video, 1200-byte packets |

## How it works

- Capture: DXGI Desktop Duplication of the first output; GDI BitBlt when
  duplication is not available (`--capture auto`).
- Colour: BGRA to NV12 on the CPU, BT.709 limited range. Larger than
  `--max-size` is point-sampled down (the software encoder is capped at
  1920x1080).
- Encode: `CLSID_CMSH264EncoderMFT`, CBR, no B-frames, low latency, GOP =
  fps, SPS/PPS on every IDR. Keyframe requests (MRM1 0x40) force an IDR.
- Send: MR02 packets paced at min(400, max(40, 4 x bitrate)) Mbit/s.
- A static screen is re-sent once a second so a late viewer gets a picture.

The log prints one `stats` line a second: size, capture/sent fps, Mbit/s,
keyframes, encode time.

## Build

```
cmake -S . -B build -A x64
cmake --build build --config Release
build\Release\JerisLinkHostTest.exe
```

`JerisLinkHostTest` checks the wire formats against the viewer's own
parsers (`../windows-client/video_receiver.hpp`, `h264_nal_summary.hpp`),
the colour values, and on Windows a loopback through the real MF encoder.
