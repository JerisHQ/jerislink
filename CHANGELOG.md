# Changelog

## v0.2.0

Smoother streaming, a Microsoft Store package, and one signed macOS host app.

Streaming and input:

- Lost video packets are retransmitted (NACK), and the bitrate follows the viewer's receiver reports (ABR).
- Windows viewer: video decode and present run on their own thread, a ready frame is presented before the next decoded one, busy frames wait instead of being dropped, and input waits and modal loops no longer stall the stream.
- Every mouse button down gets its matching up; click flags follow the held modifiers.
- macOS host: display changes are followed by callback (no more 24 h restart), no main-thread hop per clipboard poll or key, and a stricter Input Helper session lifecycle.

Windows:

- MSIX package for the Microsoft Store (package version is `VERSION` + `.0`).
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
