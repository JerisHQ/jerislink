# JerisLink Privacy Policy

Effective date: 2026-11-17

This policy covers the JerisLink Windows viewer (including the Microsoft Store
package) and the JerisLink Mac host in this repository.

## Short version

JerisLink connects your own Windows PC to your own Mac. It has no accounts, no
analytics, no crash reporting, no ads and no update check. JerisHQ does not run
any server for JerisLink and receives no data from it. Everything JerisLink
sends goes directly between the two devices you set up.

## What is sent, and where

The viewer connects only to the Mac address you enter (or start it with). The
Mac host accepts only the one viewer address it is configured for. Between
those two devices JerisLink sends:

- **Screen video** from the Mac to the PC.
- **Sound** from the Mac to the PC: the Mac's system audio mix, encoded with
  Opus at 48 kHz, only while a viewer with audio on is connected. The host
  captures it with Apple's ScreenCaptureKit (the Screen Recording permission),
  leaves out the host's own sound, and stops within about 10 seconds when the
  viewer stops asking for it. JerisLink does not install a virtual audio
  device (such as BlackHole) and does not change the Mac's output device; the
  Mac keeps playing sound as before. Start the viewer with `--audio off` to
  never request it. Audio is played and discarded; it is not recorded on either device.
- **Keyboard and mouse input** from the PC to the Mac, while the viewer
  window has focus.
- **Clipboard text** in both directions (plain text only, up to 60 KB per
  copy), while the viewer is connected with input enabled.
- **Files you choose to send**, only when you act: copy and paste (Windows
  to Mac or Mac to Windows), drop on the viewer or its Files panel, or
  "Send to JerisLink" in the Finder or in Explorer (Windows installer version
  only, not the Microsoft Store version). The file names, sizes and
  contents go to the other device, with a SHA-256 check per file. Nothing is
  sent in the background and JerisLink never opens a received file.
  Files sent from the Mac are received on the PC at once, with no confirm
  click there, and are saved only in `Downloads\JerisLink`. One transfer is
  limited to 20 GB in total.
- **Session settings** (codec, bitrate, screen size) and connection
  statistics needed to keep the stream smooth.

Nothing else is sent, and nothing is sent to any other address. Audio and
files use the same tailnet connection to the same Mac as the video.

## Encryption

JerisLink is built to run over your own [Tailscale](https://tailscale.com)
network (tailnet). It does not add its own encryption layer: traffic is
protected by Tailscale's WireGuard encryption between your devices. Tailscale
may relay that encrypted traffic through its relay servers when a direct path
is not available; Tailscale's own privacy policy applies to Tailscale.

If you point JerisLink at an address outside a tailnet, the stream, audio,
clipboard and files are sent unencrypted. Use it only over your tailnet.

## What is stored on your devices

On the Windows PC:

- Settings in the registry under `HKEY_CURRENT_USER\Software\Jeris\Jerislink`:
  the Mac's address, codec and bitrate. This PC's address is chosen
  automatically each time and is not saved; a value saved by an older
  version is deleted when you save settings.
- Diagnostic logs in your temporary folder (`%TEMP%`):
  `jerislink-viewer.log` and `jerislink-viewer-history.log` (each capped at
  about 10 MB). They contain connection details such as the two IP addresses,
  video and network statistics, and event names (for example which shortcut
  was used, or how many bytes of clipboard text were sent). They do not
  contain clipboard text or the keys you type.

On the Mac:

- Settings in `~/Library/Application Support/JerisLink/` (listen address, the
  allowed viewer address, video settings, and status files).
- Service logs in `/tmp/jerislink-*.log` and `/tmp/jerislink-*.err`, with the
  same kind of content as the Windows logs: addresses, statistics and event
  counts, not clipboard text or typed keys.

### Received files

On the Windows PC:

- Files sent from the Mac ("Send to JerisLink" in the Finder) are saved in
  `Downloads\JerisLink` in your user folder. While a file arrives it is a
  `.jlpart` file; it gets its real name only after its SHA-256 matches. An
  existing file is never replaced (`name (2).ext` instead).
- Every saved file is marked as downloaded from the internet
  (`Zone.Identifier`, ZoneId=3), so Windows SmartScreen and Office
  Protected View treat it like any other download.
- Files pasted from the Finder are saved by Explorer where you paste them.

On the Mac:

- Files sent from Windows (drop or "Send to JerisLink") are saved in
  `~/Downloads/JerisLink`, or in `~/JerisLink Received` if you refuse
  macOS access to Downloads. An existing file is never replaced.
- Received files carry the macOS quarantine mark (`com.apple.quarantine`).
- While a transfer runs, the host stages it in
  `~/Library/Caches/org.jeris.jerislink/incoming`. Partial transfers are
  removed at once; the last completed paste stays there until the next paste
  (Finder copies from it) or is removed at the next host start after 24 hours.

The logs on both devices record transfer counts, sizes and results, never
file names or contents.

None of these files leave your devices. You can delete them at any time.

### Debug mode

Debug mode is off unless you turn it on yourself by setting the environment
variable `JERISLINK_DEBUG=1` before starting JerisLink. Only in debug mode:

- the Windows viewer, when it falls back to software (CPU) video decoding,
  saves the first frame it shows as `jerislink-first-frame.bmp` in `%TEMP%`.
  This image is a picture of the Mac screen;
- the Mac input helper log records each mouse button press and release with
  a timestamp and which modifier keys (Shift, Control, Option, Command) were
  held, in `/tmp/jerislink-input-helper.err`. Key codes are never logged.

These debug files also stay on your devices.

## Data shared with JerisHQ or others

None. JerisLink does not contact JerisHQ, Microsoft, Apple or any third party.
We do not collect, sell or share personal information. If you install from the
Microsoft Store, Microsoft's own policies cover the Store itself.

## Children

JerisLink is a remote desktop tool and is not directed at children.

## Changes

Changes to this policy are made in this file, with a new effective date. The
history is in this repository.

## Contact

Questions: open an issue at <https://github.com/JerisHQ/jerislink/issues>.
