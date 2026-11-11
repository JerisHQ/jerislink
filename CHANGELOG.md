# Changelog

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
