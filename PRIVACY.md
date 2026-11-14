# JerisLink Privacy Policy

Effective date: 2026-11-14

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

- **Screen video** from the Mac to the PC. Audio is not captured or sent.
- **Keyboard and mouse input** from the PC to the Mac, while the viewer
  window has focus.
- **Clipboard text** in both directions (plain text only, up to 60 KB per
  copy), while the viewer is connected with input enabled.
- **Session settings** (codec, bitrate, screen size) and connection
  statistics needed to keep the stream smooth.

Nothing else is sent, and nothing is sent to any other address.

## Encryption

JerisLink is built to run over your own [Tailscale](https://tailscale.com)
network (tailnet). It does not add its own encryption layer: traffic is
protected by Tailscale's WireGuard encryption between your devices. Tailscale
may relay that encrypted traffic through its relay servers when a direct path
is not available; Tailscale's own privacy policy applies to Tailscale.

If you point JerisLink at an address outside a tailnet, the stream and
clipboard are sent unencrypted. Use it only over your tailnet.

## What is stored on your devices

On the Windows PC:

- Settings in the registry under `HKEY_CURRENT_USER\Software\Jeris\Jerislink`:
  the Mac's address, this PC's address (if set), codec and bitrate.
- Diagnostic logs in your temporary folder (`%TEMP%`):
  `jerislink-viewer.log` and `jerislink-viewer-history.log` (each capped at
  about 10 MB). They contain connection details such as the two IP addresses,
  video and network statistics, and event names (for example which shortcut
  was used, or how many bytes of clipboard text were sent). They do not
  contain clipboard text or the keys you type.
- If the viewer falls back to software (CPU) video decoding, it saves the first
  frame it shows as `jerislink-first-frame.bmp` in `%TEMP%`, for diagnostics.
  This image is a picture of the Mac screen. It is overwritten on each such
  session.

On the Mac:

- Settings in `~/Library/Application Support/JerisLink/` (listen address, the
  allowed viewer address, video settings, and status files).
- Service logs in `/tmp/jerislink-*.log` and `/tmp/jerislink-*.err`, with the
  same kind of content as the Windows logs: addresses, statistics and event
  counts, not clipboard text or typed keys. The input helper log also records
  each mouse button press and release with a timestamp and which modifier
  keys (Shift, Control, Option, Command) were held, to diagnose click
  problems.

None of these files leave your devices. You can delete them at any time.

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
