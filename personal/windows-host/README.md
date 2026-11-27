# JerisLink Windows host (H1 + H2, dev only)

Phase H1 of the Windows host design (2026-11-27): capture the screen, encode
H.264 with the Media Foundation software encoder and send it as MR02 to one
viewer, so the existing JerisLink viewer shows the picture.

Phase H2: keyboard and mouse from the viewer (SendInput), the remote cursor
shape, Task Manager from the overlay button, and a HOST_INFO frame that
tells the viewer it is talking to Windows.

Not in H1/H2: secure desktop (UAC prompts, lock screen, sign-in screen),
elevated windows (UIPI: this non-elevated host cannot type into them),
audio, clipboard, files, NACK/retransmit, ABR, HEVC, hardware encoders,
connection password, service/installer. The viewer's requests for those
are refused or ignored the way an older macOS host would.

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
| 38400 | TCP on `--bind` | MRC1 control: transition probe, ping, video config, input, HOST_INFO |
| 38412 | UDP on `--bind` | MRM1: keyframe request, ping, pointer moves; cursor shape back |
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

## Input (H2)

- HOST_INFO (MRC1 0x06): only to a viewer that asks for it (VIDEO_CONFIG
  caps 0x08). Its ACK is then 11 bytes ([10] = 0x01: one HOST_INFO follows)
  and the HOST_INFO goes right behind it in the same write, on each
  VIDEO_CONFIG of the connection. Platform 2 (Windows), capability bits
  (keyboard 0x01, pointer 0x02, cursor shape 0x04, Task Manager 0x08,
  POINTER_SYNC 0x20), monitor count, version. A viewer that knows it sends
  Windows keys as they are (no Mac shortcut rewrites). A 0.4.x viewer does
  not ask and gets the 10-byte ACK alone: nothing stays unread on its
  socket, so its read-only view still sees the host close the connection.
- Keys (MRC1 0x10): the wire semantic is the Windows VK (modifiers 1-4 are
  left Ctrl, Alt, Win, Shift), sent with SendInput as scan codes.
- Pointer: MRC1 0x20-0x25 and MRM1 0x24 (newest seq only), mapped from the
  picture onto the captured monitor in virtual-desktop coordinates; wheel
  and horizontal wheel as sent; left, right, middle buttons.
- POINTER_SYNC (MRC1 0x27, 10 bytes: [nx, ny BE16, MRM1 seq BE32, the
  viewer's MRM1 UDP port BE16]): a viewer that saw cap 0x20 sends one right
  in front of each button. The pointer moves by UDP and the button by TCP,
  so the button could overtake its move: the host moves to (nx, ny) first,
  then presses or releases, and MRM1 moves from that UDP socket up to that
  seq arriving later are dropped as stale. Each viewer UDP socket keeps its
  own seq order (a new socket starts at 1); one not heard from for 10 s
  starts over.
- MRC1 0x60 (the overlay's Force Quit button, "Task Manager" on Windows)
  releases held keys (mouse buttons stay as they are) and presses
  Ctrl+Shift+Esc.
- One input owner at a time. When a control connection newer than the
  current owner sends its first input frame, it becomes the only owner:
  everything the old owner holds is released on the PC first (key-ups
  and button-ups go in before the new frame), and from then on every
  input frame from the old connection is dropped, even if that viewer
  is still online. To type or click again it has to reconnect. This is
  the same rule as the viewer's reconnect takeover: the new connection
  wins and the old one is done at once. An older connection never takes
  ownership back, even after the owner closes. Connections that never
  send input (clipboard, ping) are not affected (`input.owner`,
  `input.dropped reason=not_owner`, `input_takeover` and `input_dropped`
  in `stats`). Admission, takeover and injection run under one lock, so
  a frame from the old owner can never slip in after the takeover.
- Held keys and buttons are tracked per control connection. A key-up or
  button-up ends the sender's own claim and no other (`input_up_held` in
  `stats`). The owner's keys and buttons stay down for as long as it
  holds them: nothing is released for being still, so a long press or a
  held scroll bar arrow works. They end when the owner sends the up,
  closes, or is replaced. After a reconnect the viewer sends the ups it
  owes for the old connection's presses on the new connection; by then
  the takeover has already released them, so they change nothing.
- If Windows refuses an up (SendInput fails), the key or button stays on
  record with no owner and the up is retried every 250 ms until it goes
  in (`input.up_retried`, `input_up_retry` in `stats`).
- Control connections use TCP keep-alive (3 s idle, then 10 probes 1 s
  apart) and TCP_MAXRT 13 s (data the host sent that is not
  acknowledged for 13 s closes the connection). If either cannot be set,
  the connection is closed at the handshake (`control.closed
  reason=keepalive` or `reason=maxrt`) and can never own input. So what
  an owner holds is released 0 s after the viewer reconnects and sends
  input, or about 13 s after the viewer's machine or the network goes
  away.
- Cursor shape: polled every 16 ms, sent as MRM1 0x31 on a change and once
  a second to the viewer's MRM1 address.
- Typed keys are never logged; the `stats` line has counters only.

Known limits: AltGr characters on European layouts (right Alt arrives as
Alt), Win+L (Windows ignores it from SendInput), Ctrl+Alt+Del and anything
on the secure desktop. If the viewer app hangs while its machine stays
up (the OS still answers keep-alive), what it holds stays down until it
reconnects or exits; bounding that needs an app-level heartbeat, which
the protocol does not have yet. A replaced viewer that is still online
can still move the pointer over MRM1 (UDP), but cannot press anything.

The log prints one `stats` line a second: size, capture/sent fps, Mbit/s,
keyframes, encode time, video send failures (`send_fail`, `send_err`),
input and cursor counters.

## Build

```
cmake -S . -B build -A x64
cmake --build build --config Release
build\Release\JerisLinkHostTest.exe
```

`JerisLinkHostTest` checks the wire formats against the viewer's own
parsers (`../windows-client/video_receiver.hpp`, `h264_nal_summary.hpp`,
`host_info.hpp`) and key codes (`keymap.hpp`), input decoding, pointer
mapping, the colour values, and on Windows a loopback through the real MF
encoder. It injects no input.
