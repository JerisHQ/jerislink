# Code signing policy

Status: planned. Windows binaries are not signed yet.

Free code signing for Windows is planned through SignPath.io, with a certificate from the SignPath Foundation. Once active, signed releases will state:

Free code signing provided by [SignPath.io](https://about.signpath.io), certificate by [SignPath Foundation](https://signpath.org)

## What gets signed

- Only Windows binaries built by this repository's GitHub Actions release workflow (`.github/workflows/release.yml`) on GitHub-hosted runners, from a tagged commit on `main` (tag `vX.Y.Z` matching the `VERSION` file).
- Signed files: the viewer `Jerislink.exe` and the installer `Jerislink-X.Y.Z-windows-x64-setup.exe`. Both carry ProductName "JerisLink" and ProductVersion X.Y.Z, generated from `VERSION`.
- `.github/workflows/windows.yml` is a CI check for pushes and pull requests; its output is never signed.
- Binaries built anywhere else, including developers' own machines, are never submitted for signing.

## Roles

| Role | Who |
|---|---|
| Committers and reviewers | Members of the JerisHQ GitHub organization with write access |
| Approvers (approve each signing request) | The JerisHQ organization owners |

All maintainers use multi-factor authentication on GitHub and SignPath.

## Privacy

This program will not transfer any information to other networked systems unless specifically requested by the user or the person installing or operating it.

JerisLink connects only to the peer machine you configure (over your own Tailscale tailnet). It does not send telemetry or any other data to servers operated by the JerisLink project. The optional Support component talks to a session broker that you host yourself.

## macOS

macOS builds are not covered by this policy. CI produces unsigned (ad-hoc) macOS builds; Developer ID signing and notarization are done by a maintainer on their own machine.
