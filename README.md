# JerisLink

JerisLink is a low-latency remote desktop that streams a macOS host to a Windows viewer over your own [Tailscale](https://tailscale.com) tailnet. It also includes **JerisLink Support**, a one-time remote-support flow built on the same transport.

> Status: experimental. Not security audited. Use it only on networks and machines you control.

Copyright 2026 jeris.org. Licensed under the [Apache License 2.0](LICENSE).

**[Code signing policy](CODE_SIGNING_POLICY.md)** · [Download](#download) · [Security](SECURITY.md)

## Download

Release builds are published on [GitHub Releases](https://github.com/JerisHQ/jerislink/releases). They are built by the [release workflow](.github/workflows/release.yml) on GitHub-hosted runners from a tagged commit. Windows binaries are unsigned until SignPath code signing is active (see the [code signing policy](CODE_SIGNING_POLICY.md)); macOS builds are unsigned (ad-hoc).

The version number lives in one place: the [`VERSION`](VERSION) file. The Windows file metadata (ProductName "JerisLink", ProductVersion) and the installer version are generated from it.

## Repository layout

| Folder | What it is |
|---|---|
| `personal/mac-host/` | macOS host: ScreenCaptureKit capture, VideoToolbox H.264/HEVC encode, input helper (Swift) |
| `personal/windows-client/` | Windows viewer: Media Foundation decode, D3D11 presentation, keyboard/mouse/clipboard channels (C++, CMake, Inno Setup installer) |
| `personal/tools/` | Developer tools (bitrate A/B script) |
| `support/` | JerisLink Support: one-time session broker, support agent and controller (Go), macOS Support Agent app (Swift), Windows helper script |

`support/agent/macos/build-app.sh` builds on top of `personal/mac-host`, which is why both live in one repository.

## Requirements

- Tailscale running on both machines, in the same tailnet. A direct peer path gives the lowest latency.
- macOS host: macOS 14 or later; Xcode command line tools (Swift 6).
- Windows viewer: Windows 10/11 x64 with a hardware H.264 (and optionally HEVC) decoder; Visual Studio 2022 with C++ and CMake 3.20+ to build; Inno Setup 6 for the installer.
- Support: Go (see `support/go.mod` for the version).

## Build

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

## Configure

JerisLink does not ship with any built-in addresses. Set your own Tailscale IPv4 addresses:

| Where | Setting | Meaning |
|---|---|---|
| Windows viewer | `--source-ip` flag or `JERISLINK_SOURCE_IP` env var | The Mac host's Tailscale IPv4 (required) |
| Windows viewer | `--bind-ip` (optional) | Local Tailscale IPv4; auto-detected from the Tailscale CGNAT range if not set |
| macOS host video service / A/B tool | `JERISLINK_BIND_IP`, `JERISLINK_CLIENT_IP` in `~/Library/Application Support/JerisLink/network.conf` (or env) | This Mac's and the Windows viewer's Tailscale IPv4 |
| Support macOS build | `JERISLINK_CORE_ROOT` (optional) | Path to `personal/mac-host`; defaults to the copy in this repo |
| Support Windows helper | `JERISLINK_SUPPORT_HOME` (optional) | Install folder; defaults to `%LOCALAPPDATA%\JerisLink Support` |

On Windows, set it once with `setx JERISLINK_SOURCE_IP <mac-tailscale-ipv4>`.

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability and for the known security boundaries. The Support session broker listens on loopback by default and must sit behind an HTTPS edge with abuse protection before it is exposed to the internet.

## Code signing

Windows release binaries are planned to be signed through the SignPath Foundation; see [CODE_SIGNING_POLICY.md](CODE_SIGNING_POLICY.md). Releases are built by `.github/workflows/release.yml`. macOS builds from CI are unsigned (ad-hoc).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Support the project

If JerisLink is useful to you, you can [buy me a coffee](https://buymeacoffee.com/jeris).

## License

Apache License 2.0. See [LICENSE](LICENSE), [NOTICE](NOTICE) and [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
