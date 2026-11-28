# JerisLink Windows host (H1 + H2 + H3, dev only)

Phase H1 of the Windows host design (2026-11-27): capture the screen, encode
H.264 with the Media Foundation software encoder and send it as MR02 to one
viewer, so the existing JerisLink viewer shows the picture.

Phase H2: keyboard and mouse from the viewer (SendInput), the remote cursor
shape, Task Manager from the overlay button, and a HOST_INFO frame that
tells the viewer it is talking to Windows.

Phase H3: the connection password, as the macOS host v0.4.0 (PR-C) does it
(lockout, blacklist, whitelist, takeover, UDP tags), the settings in the
registry with the key under DPAPI, and a connection settings window. There
is no mode without a password any more.

Not in H1 to H3: secure desktop (UAC prompts, lock screen, sign-in screen),
audio, clipboard, files, NACK/retransmit, ABR, HEVC, hardware encoders,
service/installer. The viewer's requests for those are refused or ignored
the way an older macOS host would.

## Running (H3)

```
JerisLinkHost.exe --connection-settings
JerisLinkHost.exe [--bind <this PC's tailnet IPv4>]
                  [--fps 30] [--bitrate 25] [--max-size 1920x1080]
                  [--capture auto|dda|gdi] [--log host.log] [--seconds N]
                  [--snapshot frame.bmp]
JerisLinkHost.exe --probe [--capture auto|dda|gdi] [--snapshot frame.bmp]
```

- Both the host and the settings window run elevated: the key is readable
  by SYSTEM and Administrators only (design D8). The host exits 77 when it
  is not elevated; `--connection-settings` asks UAC once and restarts
  itself elevated.
- No password, no network (D9): with no password set the host does not
  listen and exits 78. `--dev-no-password` and `--allow` were removed
  (exit 64). Builds are unsigned (D14).
- Where it listens (D11): `--bind`, else the registry's `BindIP`, else this
  PC's lowest tailnet IPv4 (100.64.0.0/10). Never `0.0.0.0` or another
  interface: a `--bind` outside the tailnet range exits 64. With no tailnet
  address up yet the host logs it once and waits (checks every 2 s).
  `ListenMode` `loopback` (registry only) listens on 127.0.0.1, for tests.
  `BindIP` and `ListenMode` have no field in the window and apply on the
  next start.
- `--probe` captures one frame, encodes ten and exits: a quick check that
  capture and the encoder work on this machine. It needs no password.
- `--snapshot` writes the captured frame as BMP (after 10 s of streaming,
  or at once with `--probe`).
- Exit codes: 64 bad arguments, 77 not elevated, 78 no password, or the
  settings do not read, or the registry's listen settings are wrong.

## Connection settings window

`JerisLinkHost.exe --connection-settings`, the same parts and Chinese
messages as the macOS host's 連線設定 window, in the viewer's green or blue
theme (`../windows-client/ui_theme.hpp`):

- 密碼: set or change, typed twice; at least 10 characters with an upper
  case letter, a lower case letter and a symbol. There is no 清除密碼
  button (D9). Every set makes a new salt and keeps the host id.
- 白名單: tailnet addresses, one per line (commas and spaces also split).
  Empty: any address may try the password. Anything outside 100.64.0.0/10
  is refused.
- 黑名單: add or remove an address. It takes effect at once on a running
  host: its connections are closed and it is refused from then on.
- Recent wrong passwords, per address.
- 主題: green or blue (the window only).

A running host sees every change through a registry watch
(RegNotifyChangeKeyValue, plus a 1 s check).

## Registry (D7, D8)

`HKLM\SOFTWARE\Jeris\JerisLinkHost`, 64-bit view (Users can read it, only
Administrators and SYSTEM write):

| Value | Type | Meaning |
| --- | --- | --- |
| `ListenMode` | REG_SZ | `tailnet` (default) or `loopback` |
| `BindIP` | REG_SZ | a tailnet IPv4 on this PC; absent or empty: the lowest one |
| `AllowedIPs` | REG_MULTI_SZ | the whitelist; empty: any address |
| `BlockedIPs` | REG_MULTI_SZ | the blacklist, `ip<TAB>unix seconds<TAB>reason` per row |
| `PasswordSet` | REG_DWORD | 1 once a password is set (for display; `Secret` decides) |
| `Theme` | REG_SZ | `green` (default) or `blue` |
| `LogPath` | REG_SZ | the host log when `--log` is not given |
| `Serial` | REG_QWORD | moved by every write, read as the change stamp |
| `Secret\Key` | REG_BINARY | DPAPI (`CRYPTPROTECT_LOCAL_MACHINE`) of K, salt, iterations, host id; `Secret`'s DACL is SYSTEM and Administrators only, not inherited |
| `Journal\PendingBlocks` | REG_MULTI_SZ | blocks not yet written to `BlockedIPs` |
| `Failures\Records`, `Failures\Times` | | the window's failure list |

The password itself is never stored or logged: only K =
PBKDF2-SHA256(password, salt, 600000), under DPAPI. Read-modify-writes run
under the mutex `Global\JerisLinkHostConfig` (SYSTEM and Administrators
only), so the host adding a block and the window removing one cannot lose
each other's change.

## Password (same rules as the macOS host v0.4.0)

- Every TCP connection authenticates first: MRC1 0x05 CHALLENGE, 0x03
  RESPONSE, 0x04 RESULT, the MACs of `../windows-client/conn_auth.hpp` and
  `../protocol/auth_vectors.json`. 5 s for the whole RESPONSE. No new wire
  in H3.
- Wrong passwords, per address: each 5th locks it for 5, 10, then 15
  minutes (RESULT locked with the seconds left), the 20th blacklists it
  (persisted). 20 wrong passwords from anyone inside 60 s stop every
  challenge for 5 minutes. A block that could not be written goes to a
  pending journal and keeps the host shut until it is written.
- A whitelist that is not empty closes every other address's connection
  before any challenge (`Control reject ... expected=whitelist`). The
  blacklist wins over the whitelist.
- Takeover: a manual control login with the right password takes over.
  Every older connection is void at once and closed, its viewer is told
  REPLACED, and nothing of the old session is reused: every reconnect is a
  fresh password exchange. A reconnect the viewer makes on its own (the
  `jl-auto1` trailer) never takes over while a control connection is open.
  Clipboard, file and ping channels get in only on the newest control
  session.
- A password or whitelist change while the host runs voids every
  connection at once, with no notice (the viewer reconnects and has to log
  in again). The macOS host restarts its control service instead. REPLACED
  is sent only on a takeover.
- After a failure RESULT, a lock or block RESULT that answers a RESPONSE,
  and REPLACED, the host sends
  FIN and reads and drops what the viewer still sends until it closes, for
  at most 1 s, then closes. A close with input unread (a bad header or a
  wrong-length RESPONSE leaves its payload behind) is an RST, and Windows
  can throw the RESULT away before the viewer reads it. The macOS host
  drains only after REPLACED.
- Input and VIDEO_CONFIG are taken only on the control channel. Input
  owners (H2, below) are numbered by the session broker's token, so a
  newer login is always the newer owner.
- A void (a takeover, a password or whitelist change, a block) also ends
  the input owner's turn at once, before a takeover's AUTH_OK goes out:
  what it holds goes up, its MRM1 socket is unbound, and an input frame
  of it that was already going in lands first; nothing of it goes in
  afterwards, even a frame read before the void (the macOS host's r11
  rule; `input.owner_voided`, `input.dropped reason=voided`,
  `input_owner_voided` in `stats`).
- UDP: only the session viewer's address is heard, and every datagram
  both ways carries the 8-byte tag under the session key
  (`../windows-client/udp_tag.hpp`). MRM1 is checked in the macOS host's
  order: session, address, tag (`udp.bad_tag`, rate limited), format, then
  a 64-packet anti-replay window that starts fresh with each session. A
  ping from a blacklisted or locked-down address gets no pong.
- Video and the cursor shape go only to the session viewer (video to its
  38402), tagged. With no session the stream idles (`stream.idle
  reason=no_session`); each new session starts on a keyframe.

Log lines: `auth.ok`, `auth.fail`, `auth.locked`, `auth.blocked`,
`auth.global_locked`, `auth.replaced`, `auth.policy_changed`,
`auth.block_added`, `auth.block_removed`, `control.open ... auth=password`,
`mrm1.session`, `stream.start ... gen=`.

## Ports (same as the macOS host)

| Port | Proto | Use |
| --- | --- | --- |
| 38400 | TCP on the bind address | MRC1 control: AUTH, transition probe, ping, video config, input, HOST_INFO |
| 38412 | UDP on the bind address | MRM1: keyframe request, ping, pointer moves; cursor shape back (tagged) |
| 38402 | UDP to the session viewer | MR02 video, 1200-byte packets plus the 8-byte tag |

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
input and cursor counters, and (H3) the password and UDP counters
(`auth_fail`, `auth_rejected`, `auth_old_viewer`, `auth_resume_refused`,
`input_owner_voided`, `replaced`, `udp_no_session`, `udp_rejected`, `udp_bad_tag`, `udp_bad`,
`udp_replay`, `udp_stale`, `udp_late_ok`, `pong_drops`, `session_drops`).

## Build

```
cmake -S . -B build -A x64
cmake --build build --config Release
build\Release\JerisLinkHostTest.exe
build\Release\JerisLinkHostAuthTest.exe ..\protocol\auth_vectors.json
```

`JerisLinkHostTest` checks the wire formats against the viewer's own
parsers (`../windows-client/video_receiver.hpp`, `h264_nal_summary.hpp`,
`host_info.hpp`) and key codes (`keymap.hpp`), input decoding, pointer
mapping, the colour values, and on Windows a loopback through the real MF
encoder. It injects no input.

`JerisLinkHostAuthTest` (H3) checks the password exchange against
`../protocol/auth_vectors.json`, CNG against the portable HMAC, the
lockout, blacklist, whitelist and takeover rules, the UDP tags and replay
window, the settings texts, and the viewer's own client code
(`../windows-client/conn_auth.hpp`) against this host over loopback. On
Windows it also runs the registry store under
`HKCU\Software\JerisTest\<unique>` (never HKLM) and deletes it. It also
builds and runs on Linux (the portable parts):

```
c++ -std=c++20 -I. -I.. -o auth_test auth_test.cpp && ./auth_test ../protocol/auth_vectors.json
```
