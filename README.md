# JerisLink

JerisLink is a low-latency remote desktop for your [Tailscale](https://tailscale.com) tailnet: a Mac runs the host, a Windows PC runs the viewer, and you control the Mac from the PC. The connection stays inside your tailnet. There is no JerisLink account and no JerisLink server.

> Status: experimental. Not security audited. Use it only on networks and machines you control.

<!-- TODO(screenshot): the Windows viewer showing a Mac desktop. Use a real capture, not a mock-up. -->
<!-- TODO(demo-gif): 10 to 20 seconds of a real session: connect on the launch screen, move a window, send a file. -->

**[Get the Windows viewer from the Microsoft Store](https://apps.microsoft.com/detail/9NM3VWQ9MD7N)** · [Mac host and other downloads (GitHub Releases)](https://github.com/JerisHQ/jerislink/releases/latest) · [Quick start](#quick-start) · [Security](SECURITY.md)

## Download

| What | Where | Signing |
|---|---|---|
| Mac host (Apple silicon, macOS 14 or later) | `JerisLink-<version>-macos-arm64.zip` on [GitHub Releases](https://github.com/JerisHQ/jerislink/releases/latest) | Developer ID signed and notarized by Apple, ticket stapled |
| Windows viewer (recommended) | [Microsoft Store](https://apps.microsoft.com/detail/9NM3VWQ9MD7N) | Signed by Microsoft through the Store |
| Windows viewer, installer | `Jerislink-<version>-windows-x64-setup.exe` on GitHub Releases | Not code-signed yet |
| Windows viewer, no install | `Jerislink-<version>-windows-x64-portable.zip` on GitHub Releases | Not code-signed yet |

Every release has a `SHA256SUMS.txt` to check the downloads against. Details: [Code signing](#code-signing).

## Quick start

You need a Mac with Apple silicon on macOS 14 or later, a Windows 10 or 11 x64 PC, and Tailscale signed in to the same tailnet on both. Note each machine's Tailscale IPv4 address (`100.x.y.z`, shown in the Tailscale menu or by `tailscale ip -4`).

On the Mac:

1. Download `JerisLink-<version>-macos-arm64.zip` from the [latest release](https://github.com/JerisHQ/jerislink/releases/latest), unpack it, and move `JerisLink.app` into the `Applications` folder in your home folder (`~/Applications`; create it if it is missing).
2. Open `JerisLink.app`. It starts its background services. Allow what macOS asks for in System Settings > Privacy & Security: **Screen Recording** for JerisLink and **Accessibility** for JerisLink Input Helper. If it asks, also turn on JerisLink under General > Login Items & Extensions. Open the app again: all three services should show `enabled`.
3. Allow your PC. The host app's **連線設定…** window has an allowed-address list (白名單), but it can only save to `listen.plist`, and the app does not create that file yet. So create it once in Terminal, with the **Windows PC's** Tailscale IPv4 in place of `100.x.y.z`:

   ```sh
   mkdir -p ~/Library/Application\ Support/JerisLink
   cd ~/Library/Application\ Support/JerisLink
   /usr/bin/lockf -k listen.plist.lock /usr/libexec/PlistBuddy \
     -c 'Add :mode string tailnet' -c 'Add :clientIP string 100.x.y.z' listen.plist
   ```

4. Set a connection password: open `JerisLink.app`, click **連線設定…** (connection settings) and set it there. Without a password, the allowed PC connects on its address alone. More PCs and blocked addresses are added in the same window from now on.

On the PC:

5. Install JerisLink from the [Microsoft Store](https://apps.microsoft.com/detail/9NM3VWQ9MD7N), or the installer from GitHub Releases, and open it.
6. On the launch screen, type the **Mac's** Tailscale IPv4 in **Mac host address** and the password in **Connection password**, then click **Connect to Mac**. The address is saved for the next start; turn on **Remember password on this PC** to skip typing the password next time.

This PC's own address is chosen automatically. More detail: [Mac host install guide](personal/mac-host/Deploy/README.md) and [Windows viewer notes](personal/windows-client/README-Windows.txt).

## Features

- The Mac's main display at its native resolution, up to 60 fps. Hardware H.264 or HEVC encoding on the Mac (VideoToolbox), hardware decoding on the PC (Media Foundation, Direct3D 11).
- Lost video packets are sent again, and the bitrate follows the network.
- The Mac's sound plays on the PC (Opus), with a volume slider.
- Keyboard and mouse, with Mac or Windows keyboard layout presets. The overlay can open the Mac's Force Quit window.
- Text clipboard in both directions.
- Files in both directions: copy in Explorer and paste in Finder or the other way round, drag files onto the viewer, or right-click and use Send to JerisLink in Explorer or the Finder. Files that arrive on Windows carry the internet zone mark.
- Connection password. The password itself is never sent; the Mac keeps only a key derived from it, in the Keychain. Repeated wrong passwords lock that address out for a while, then block it. With a password set, every video, audio and mouse packet is tied to the logged-in session, and other packets are dropped. Allowed and blocked addresses are edited in the host app's 連線設定 window; the first allowed address is set once in Terminal (quick start, step 3).
- Launch screen with a green or blue theme, and an overlay during the session instead of a menu bar.
- No analytics, crash reporting or update check. See [PRIVACY.md](PRIVACY.md).

## Code signing

- **macOS:** the [release workflow](.github/workflows/release.yml) signs `JerisLink.app` with a Developer ID certificate, has Apple notarize it and staples the ticket (`personal/mac-host/Deploy/notarize.sh`). A zip whose name ends in `-unsigned.zip` was built without the signing secrets and is only ad-hoc signed (so far only v0.1.0); do not use it.
- **Windows, Microsoft Store:** the Store delivers the package signed by Microsoft. A release can also carry `Jerislink-<version>-windows-x64-store-signed.msix`, a copy of that Store-signed package, which [`store-msix-to-release`](https://github.com/JerisHQ/jerislink/blob/main/.github/workflows/store-msix-to-release.yml) downloads from the Store and checks before attaching it.
- **Windows, GitHub Releases:** the installer and the portable `Jerislink.exe` are not code-signed yet, so Windows may warn before running them. Signing through the SignPath Foundation is planned; see the [code signing policy](CODE_SIGNING_POLICY.md).

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability and for the known security boundaries. The Support session broker listens on loopback by default and must sit behind an HTTPS edge with abuse protection before it is exposed to the internet.

## For developers

### Repository layout

| Folder | What it is |
|---|---|
| `personal/mac-host/` | macOS host: ScreenCaptureKit capture, VideoToolbox H.264/HEVC encode, input helper (Swift) |
| `personal/windows-client/` | Windows viewer: Media Foundation decode, D3D11 presentation, keyboard/mouse/clipboard channels (C++, CMake, Inno Setup installer) |
| `personal/tools/` | Developer tools (bitrate A/B script) |
| `support/` | JerisLink Support: one-time remote-support flow on the same transport. Session broker, support agent and controller (Go), macOS Support Agent app (Swift), Windows helper script. Not part of the releases. |

`support/agent/macos/build-app.sh` builds on top of `personal/mac-host`, which is why both live in one repository.

The version number lives in one place: the [`VERSION`](VERSION) file. The Windows file metadata (ProductName "JerisLink", ProductVersion) and the installer version are generated from it.

### Requirements

- Tailscale running on both machines, in the same tailnet. A direct peer path gives the lowest latency.
- macOS host: macOS 14 or later; Xcode command line tools (Swift 6).
- Windows viewer: Windows 10/11 x64 with a hardware H.264 (and optionally HEVC) decoder; Visual Studio 2022 with C++ and CMake 3.20+ to build; Inno Setup 6 for the installer.
- Support: Go (see `support/go.mod` for the version).

### Build

macOS host:

```sh
cd personal/mac-host
swift build -c release
# Disposable dev build of JerisLink.app without a signing identity:
JERISLINK_ALLOW_ADHOC=1 ./Deploy/build-apps.sh
./Deploy/verify-bundle.sh .dist/JerisLink.app
```

Install, background services and macOS permissions: `personal/mac-host/Deploy/README.md`. Signing (stable local identity, Developer ID, notarization): `personal/mac-host/Deploy/SIGNING.md`.

Windows viewer (Developer Command Prompt for VS 2022):

```bat
cd personal\windows-client
cmake -S . -B build -A x64
cmake --build build --config Release --target Jerislink
```

Support:

```sh
cd support
go test -race ./...
go build ./cmd/...
```

### Configuration reference

JerisLink does not ship with any built-in addresses. Normal setup is the [quick start](#quick-start); everything below is optional or for older installs.

| Where | Setting | Meaning |
|---|---|---|
| Windows viewer | **Mac host address** on the launch screen, saved as `HostIp` in `HKCU\Software\Jeris\Jerislink` | The Mac's Tailscale IPv4. The normal way to set it. |
| Windows viewer | `--source-ip <ipv4>` (optional) | The Mac's address for this start; skips the launch screen. |
| Windows viewer | `JERISLINK_SOURCE_IP` env var (optional, older setups) | Used only when no address is saved and none is given with `--source-ip`. |
| Windows viewer | `--bind-ip` (optional) | This PC's Tailscale IPv4; chosen automatically from the Mac address if not set |
| macOS host | `~/Library/Application Support/JerisLink/listen.plist` | Listen mode, allowed viewer addresses (`clientIP`, `allowedIPs`), blocked addresses. Create it, or change `mode`, through `lockf` as in the quick start; once it exists, the host app's 連線設定 sets the password and edits the allowed and blocked addresses; see the [Mac host install guide](personal/mac-host/Deploy/README.md#listen-endpoint) |
| macOS host (without `listen.plist`) / A/B tool | `JERISLINK_BIND_IP`, `JERISLINK_CLIENT_IP` in `~/Library/Application Support/JerisLink/network.conf` (or env) | This Mac's and the Windows viewer's Tailscale IPv4 |
| Support macOS build | `JERISLINK_CORE_ROOT` (optional) | Path to `personal/mac-host`; defaults to the copy in this repo |
| Support Windows helper | `JERISLINK_SUPPORT_HOME` (optional) | Install folder; defaults to `%LOCALAPPDATA%\JerisLink Support` |

To see what a viewer start would use without connecting: `Jerislink.exe --print-config %TEMP%\jerislink-config.txt`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Support the project

If JerisLink is useful to you, you can [buy me a coffee](https://buymeacoffee.com/jeris).

## License

Copyright 2026 jeris.org. Apache License 2.0. See [LICENSE](LICENSE), [NOTICE](NOTICE) and [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
