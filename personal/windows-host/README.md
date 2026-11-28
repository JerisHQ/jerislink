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
  starts over. The 10-byte 0x27 format (with cap 0x20) was approved by
  Morris on 2026-11-28 at 01:19 HKT. It is the only wire addition in H2.
- H2 development builds must be used in pairs: a host and a viewer from the
  same build. Mixing an earlier H2 development viewer or host with this one
  is not supported. For example, a build with the early 8-byte 0x27
  (8f8a33b) and a build with the 10-byte 0x27 each drop the other's
  POINTER_SYNC as malformed. Supported: 0.4.x viewers (with TCP moves,
  below) and the viewer from this build with this host, and the viewer from this build with the macOS
  host.
- MRM1 moves are taken from one UDP socket only: the one the input owner
  named in its own POINTER_SYNC (the owner's viewer address and the port
  its last 0x27 named). The cursor shape goes to that socket and nowhere
  else. Moves from any other socket, and every move while there is no
  owner, are dropped (`pointer_udp_not_owner` in `stats`).
  - This viewer names its socket on each new control connection with its
    first move (a 0x27, then a 0x24 at the same position), so hover works
    without a click. An H2 viewer before r9 names it only with a click;
    until then its moves are dropped.
  - A 0.4.x viewer never sends 0x27, so it names no socket and none of its
    MRM1 moves goes in: before its first click there is no owner
    (`pointer_udp_not_owner`), after it the owner named no socket
    (`mrm1.legacy_off` in the host log, `pointer_udp_legacy_off` in
    `stats`). It gets no cursor shape. Why (r14, Pepper's review of
    524e4d1): an MRM1 datagram carries nothing that ties its UDP socket to
    a control connection, and the host cannot tell two viewers on one PC
    apart by address, port, timing or connection count. A 0.4.x viewer
    whose control connection failed keeps sending MRM1 from the same PC as
    another viewer, so any rule that takes a socket the owner did not name
    can move the pointer for the wrong viewer. A 0.4.x viewer with this
    host always runs with TCP moves (`--mouse-move-transport tcp`, below).
  - When the owner changes (a takeover, its close, going quiet), the
    binding goes with it: the new owner moves nothing by UDP until its own
    0x27 names a socket, and the old socket gets no cursor shape. A
    replaced viewer's late datagrams never move the pointer, and the new
    owner's drag and cursor shape are not disturbed.
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
  in (`input.up_retried`, `input_up_retry` in `stats`). Until every such
  up went in, only key and button ups are injected; every other input
  frame (and every MRM1 move) is dropped, not kept for later
  (`input.dropped reason=up_pending`, `input_up_pending` and
  `pointer_udp_up_pending` in `stats`). So a new owner's C never goes in
  under an old owner's Ctrl. Dropped rather than kept: Windows refuses
  input while the secure desktop, a UAC prompt or a higher-integrity window
  has it, and a replay seconds later would land wherever the user is by
  then. The Task Manager chord stops at the first down Windows refuses and
  owes the ups of what it pressed.
- Liveness (a hung viewer app): this viewer sends the existing MRC1 ping
  (0x01) on its control connection once a second from its input thread
  (to a Windows host only; no new message or capability bit). Every
  viewer's first frame on a connection is one start-up ping, and that ping
  does not count. Only a ping after the first frame (a liveness ping) arms
  the connection (`input.liveness from=ping`), and each one restarts the
  5 s. This viewer sends one as the start-up connection goes live, and two
  at the start of every reconnect, always before any input. So its
  connection is armed before its first key or click (`input.open
  liveness=on`). A 0.4.x viewer never sends a ping after the first frame
  and is never armed (`input.open liveness=off`). Asking for HOST_INFO
  (VIDEO_CONFIG caps 0x08) does not arm a connection: r10 did that, but H2
  r1 to r8 development viewers ask for HOST_INFO and never ping. An armed
  owner that sends no ping for more than 5 s loses ownership and what it
  holds goes up (checked every 250 ms: `input.owner_silent`,
  `input_silenced` in `stats`); its connection is closed at once (its
  reader checks every 50 ms: `control.silenced_closed
  reason=liveness_timeout`), its slot is free again, and the viewer
  reconnects. Worst case 5.25 s plus the last ping's one-way
  time after the hang; at least about 4 s (the last ping went out up to a
  second before). 1 s pings: a lost segment's retransmission or a short UI
  stall (a modal loop, a slow frame) stays well inside 5 s. A viewer that
  never pings (an older viewer, a viewer of the macOS host) is never
  timed out: TCP alone, as before.
- Control connections use TCP keep-alive (3 s idle, then 10 probes 1 s
  apart) and TCP_MAXRT 13 s (data the host sent that is not
  acknowledged for 13 s closes the connection). If either cannot be set,
  the connection is closed at the handshake (`control.closed
  reason=keepalive` or `reason=maxrt`) and can never own input. So what
  an owner holds is released 0 s after the viewer reconnects and sends
  input, about 5 s after this viewer's app hangs, or about 13 s after the
  viewer's machine or the network goes away.
- Cursor shape: polled every 16 ms, sent as MRM1 0x31 on a change and once
  a second, to the UDP socket MRM1 moves are taken from now (above), and at
  once to a new one; while there is none, nowhere.
- Typed keys are never logged; the `stats` line has counters only.

Known limits: AltGr characters on European layouts (right Alt arrives as
Alt), Win+L (Windows ignores it from SendInput), Ctrl+Alt+Del and anything
on the secure desktop. An older viewer (no liveness pings) that hangs
while its machine stays up (the OS still answers keep-alive) keeps what
it holds down until it reconnects or exits. After a hang of more than 5 s
the host closes the connection; a frame the viewer sends just as it does
is lost, and what follows goes on the reconnect. A replaced viewer that
is still online can neither move the pointer nor press anything. A 0.4.x
viewer started without `--mouse-move-transport tcp` (UDP moves are its
default) cannot move the Windows pointer: its moves are dropped (above),
its clicks go in where the host pointer is, not where it clicked (a click
queued for a reconnect goes in at its own position), and it gets no cursor
shape. A viewer (any) gets no cursor shape before it names a socket (a
read-only view, this viewer before its first move), and a 0.4.x viewer
never gets one.

A 0.4.x viewer with this host: always start it with TCP moves, from a
command prompt in its folder on the viewer PC:

```
Jerislink.exe --source-ip <host tailnet IP> --mouse-move-transport tcp
```

If its mouse does not move the Windows pointer (`mrm1.legacy_off` in the
host log), it was started without the option: quit it and start it again
with it. Nothing else brings its UDP moves back (no host restart, no other
PC): with this host they never go in (`testLegacyUdpOff` and
`testNoSessionLateUdp` in `host_test.cpp`).

`--mouse-move-transport tcp|udp` is a command-line option of 0.4.0 and
0.4.1 (`viewer_options.hpp`; udp is the default and there is no setting
for it), so it goes on every start, for example in a shortcut. With tcp,
every move goes on the control connection (MRC1 0x24), in order with the
clicks: each press and release goes in right behind the move to where it
was made. Hover, clicks, double clicks and drags then go in where they were
made, with other viewers on the same PC, after a port change and after a
reconnect (`testLegacyTcpMoves` in `host_test.cpp`). The cost: with tcp a
0.4.x viewer opens no MRM1 socket (`udp_plan.hpp`), so it gets no cursor
shape and sends no keyframe requests (the host sends a keyframe every
second, so a broken picture heals within about 1 s). NACK, ABR and audio
are not in H2 either way. A viewer from this
build does not need the option: it names its socket with 0x27. This is
the Windows host only; nothing changes for the macOS host.

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
