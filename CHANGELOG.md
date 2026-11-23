# Changelog

## v0.4.1

The Microsoft Store (MSIX) viewer gets "Send to JerisLink" in the Explorer right-click menu (GitHub #70, Gitea #65).

Windows viewer, Microsoft Store (MSIX) build:

- Right-click files or folders in Explorer and pick "Send to JerisLink" (Windows 11: in the first menu, no Show more options). They go to `~/Downloads/JerisLink` on the Mac by default, the same as dragging them onto the viewer; when access to Downloads is refused, the Mac uses `~/JerisLink Received` instead. Tested on Windows 11. The package needs Windows 10 1809 or later, but the menu has not been tested on Windows 10 yet. If the viewer is installed but the right-click entry does not appear, drag files onto the viewer instead.
- The command is an `IExplorerCommand` shell extension (`JerisLinkSendTo.dll`, served by the package's COM surrogate). It only starts `Jerislink.exe --send-to <paths>` and returns, so Explorer never waits on a transfer; the viewer sends through its existing named pipe and dialogs.
- A selection too long for one command line shows the "too many items" dialog. The entry is hidden for a selection that is not all on disk, and an item without a file system path makes the run refuse the whole request.
- Each menu entry hands off only to its own build: the Store entry to the Store viewer, the installer's Send to > JerisLink entry (unchanged) to the installer viewer. That viewer must already be connected to the Mac; otherwise it says JerisLink is not connected and nothing is sent.
- The Files panel hint for the Store build points at the right-click command.

CI (GitHub `msix` and `windows` workflows):

- The package build checks the DLL's CRT imports, exports and its hash inside the package, then installs the package and activates the command through the COM surrogate. A new shell extension test (COM factory, title, icon, state, and Invoke starting the exe with the exact paths) runs in the `windows` workflow.

Docs:

- `README-Windows.txt`, `INSTALL-SIDELOAD.txt`, `PRIVACY.md` and the Mac host deploy README no longer say the Store version has no Send to entry.

Packaging:

- Version 0.4.1 everywhere: `VERSION`, the macOS bundle versions, and MSIX `0.4.1.0` (GitHub `msix` workflow).

## v0.4.0

Connection password: the Mac host can require a password before a viewer connects, and video, audio and input over UDP are bound to the logged-in session.

Connection password (PR-A host core, PR-B viewer, PR-C UDP + host UI):

- New AUTH handshake on every TCP channel (control, clipboard, file, ping): the host sends a challenge, the viewer answers with an HMAC of a PBKDF2-SHA256 key (600000 iterations), and the host proves it knows the key too. The password itself is never sent, stored or logged.
- The Mac keeps the derived key in the Keychain (`org.jeris.jerislink.connpw`, this device only).
- Limits per IP: 5 wrong tries wait 5 min, 10 wait 10 min, 15 wait 15 min, 20 put the IP on the blacklist. 20 failures within 60 s host-wide make every IP wait 5 min.
- With a password set, every UDP datagram (mouse, video, audio) carries an 8-byte session tag; untagged or wrong-tag packets are dropped. Video and audio go only to the IP of the logged-in control session.
- Host app: new connection settings (連線設定) to set, change or clear the password and edit the whitelist and blacklist (`allowedIPs` / `blockedIPs`), with a yellow warning while no password is set. Also `JerisLinkHost --connection-settings`.
- Windows viewer: password field with Show and "Remember password on this PC" (off by default; the key is sealed with DPAPI for the current user). Wrong password, lockout countdown, blocked and "host too old" show as one error line on the launch screen, no dialog.
- Takeover (password mode): a manual Connect from a second viewer takes over the session. The old viewer's control connection gets "replaced" (or is reset if a reply to it was only partly sent) and its remaining file-transfer steps stop; a file move that already passed its check can still finish. An automatic reconnect gets in only when no other control session is open.
- No password set (transition mode): the host still checks the whitelist and the blacklist, and 0.3.x viewers keep working when their IP passes. The viewer shows "No connection password set on this Mac". On first start, an old `listen.plist` with `clientIP` and no `allowedIPs` gets `allowedIPs = [clientIP]` and keeps `clientIP`; the old file is kept as `listen.plist.pre-0.4`. The whitelist follows `clientIP` until a whitelist is saved in the host app.

Mac host:

- The host stops capture, encoding and sending when no valid UDP packet has come from the viewer for 15 s (60 s for a session that has not sent a keep-alive yet), and resumes with a keyframe when it comes back. The control connection uses TCP keepalive to drop a dead peer in about 25 s.

Security fixes from the v0.3.0 review:

- Files sent to Windows are delivered only with the Internet zone mark (Mark of the Web) in place, and the final file stays held until delivery is done.
- File manifest size overflow fixed; Force Quit relay hardened.

Microsoft Store publishing (GitHub `msstore-publish` workflow, started by a published GitHub release or by hand):

- `msstore-publish` uploads the package file with CLI v0.4.4. Before the upload it stops if Partner Center already has a pending submission; a draft opened between that check and the upload could still be deleted by the CLI. `--noCommit` keeps the new submission as a draft for a manual Submit in Partner Center. Afterwards the Store CLI credential and token caches are removed.

Packaging:

- Version 0.4.0 everywhere: `VERSION`, the macOS bundle versions, and MSIX `0.4.0.0` (GitHub `msix` workflow).

## v0.3.0

Remote audio, file transfer between Windows and the Mac, keyboard layout presets, and a new viewer launch screen.

Audio:

- The Mac host sends system audio to the Windows viewer, encoded with Opus, with drift control and audio-aware ABR (PR-A1, A2).
- Output device changes on Windows are handled without a restart; the viewer has a volume slider.

File transfer (Windows <-> Mac, inside the existing tailnet connection):

- Copy files in Windows and paste them in Finder; copy in Finder and paste in Explorer (F2, F3).
- Files panel with drag-and-drop to send from Windows to the Mac (F4).
- "Send to JerisLink" in Explorer (F5a) and in the Finder (F5b). Files sent to Windows land in `Downloads\JerisLink` and get the Internet zone mark (Zone.Identifier).
- Cmd+V of files is refused while a transfer is running, with a busy notice.
- "Send to JerisLink" in the Finder now reaches the viewer after a second viewer window replaced the first session; before, it said JerisLink was not open.
- The Microsoft Store (MSIX) version has no "Send to" entry in Explorer. Drag files onto the viewer window or its Files panel instead.
- New file session handshake (FILE_HELLO) with path safety checks.

Windows viewer:

- Launch screen and in-session overlay replace the menu bar; dark settings and volume dialogs.
- Overlay "Force Quit" opens the Mac's Force Quit Applications window (Cmd+Option+Esc).
- Settings no longer has address fields. The Mac address is typed on the launch screen, this PC's address is always chosen automatically, and both are shown read-only in Connection info.
- Keyboard: Mac and Windows layout presets, Ctrl+X/S/F and Ctrl+Y mapping; key translation moved to `keymap.hpp` with golden tests.
- Per-phase `loop.slow_iter` timing at 16 ms (PR-G5).
- H.264 on capped displays: the encoded size is acknowledged correctly.

Packaging:

- MSIX sideload test packages (GitHub `msix` workflow) are signed with a fixed test certificate when it is configured, otherwise with a throwaway one.
- Version 0.3.0 everywhere: `VERSION`, the macOS bundle versions, MSIX `0.3.0.0` (GitHub `msix` workflow), and the build id `0.3.0 · <sha>`.

## v0.2.0

Smoother streaming, a Microsoft Store package, and one signed macOS host app.

Streaming and input:

- Lost video packets are retransmitted (NACK), and the bitrate follows the viewer's receiver reports (ABR).
- Windows viewer: video decode and present run on their own thread, a ready frame is presented before the next decoded one, busy frames wait instead of being dropped, and input waits and modal loops no longer stall the stream.
- Every mouse button down gets its matching up; click flags follow the held modifiers.
- macOS host: display changes are followed by callback (no more 24 h restart), no main-thread hop per clipboard poll or key, and a stricter Input Helper session lifecycle.

Windows:

- MSIX package for the Microsoft Store, built by the GitHub `msix` workflow on pull requests, pushes and manual runs (package version is `VERSION` + `.0`).
- Viewer logs are written in the background with 10 MB caps. The first-frame BMP and the per-click log are written only with `JERISLINK_DEBUG=1`.
- New v2.0 JerisLink icon on macOS and Windows.
- Privacy policy in `PRIVACY.md`.

macOS host: one app, and Developer ID signing.

- The host ships as one `JerisLink.app`. The Input Helper is bundled inside it (`Contents/Helpers/JerisLink Input Helper.app`) and still runs as its own process with its own bundle identifier, so a crash in one does not stop the other.
- Autostart and restart now use `SMAppService` agents registered by the app itself (`--register`, `--unregister`, `--status`). The hand-installed LaunchAgents and the zsh watchdogs are removed; `JerisLinkHost --service video` replaces the video watchdog and still reads `network.conf` and `video-settings.plist`.
- Opening `JerisLink.app` registers the agents, asks for Screen Recording and shows their status. The Input Helper asks for Accessibility when it starts.
- Ports, the Windows viewer and the wire protocol are unchanged.
- Hardened runtime on both executables. `build-apps.sh` signs with Developer ID (`JERISLINK_DEVELOPER_ID`), the local identity, or ad-hoc (`JERISLINK_ALLOW_ADHOC=1`). New `notarize.sh` and `verify-bundle.sh`.
- Release workflow: the macOS job signs, notarizes and staples when the signing secrets are set, and builds the unsigned zip otherwise. The macOS CI workflow builds and verifies the bundle.
- `install-production.sh` migrates a Mac from the old two-app layout; `network.conf` and `video-settings.plist` are kept. Screen Recording and Accessibility must be approved again once after migration.
- Requires macOS 14 or later.

## v0.1.0

First public release.

- Release workflow (`.github/workflows/release.yml`): on a `v*` tag, builds the Windows viewer, the Inno Setup installer and the unsigned macOS host apps on GitHub-hosted runners, and creates a draft GitHub release.
- The version now lives in one place, the `VERSION` file. Windows file metadata (ProductName "JerisLink", ProductVersion), the app manifests, the installer and the macOS bundle version are generated from it.
- Code signing policy: SignPath attribution wording and privacy statement.

## First public source release

- First public source release of JerisLink (macOS host, Windows viewer) and JerisLink Support.
- No built-in network addresses: the host address is set with `--source-ip` / `JERISLINK_SOURCE_IP`, and the macOS watchdog reads `network.conf`.
- Go module path is now `github.com/JerisHQ/jerislink/support`.
- Licensed under Apache-2.0.

Earlier development history (v0.0.4 to v0.0.9.5) is summarised in `personal/docs/RELEASES.md`.
