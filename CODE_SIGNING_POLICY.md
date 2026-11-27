# Code signing policy

Status: planned. The Windows viewer and installer that this repository's GitHub release workflow builds are not code-signed yet. The Microsoft Store package, also attached to some GitHub Releases as `-store-signed.msix`, is signed by Microsoft and is not covered by this policy (see [Microsoft Store](#microsoft-store)).

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

macOS builds are not covered by this policy. The release workflow signs the macOS host with a Developer ID certificate, has Apple notarize it and staples the ticket when the signing secrets are set; without them it builds an ad-hoc signed zip whose name ends in `-unsigned.zip`. The macOS CI workflow (`.github/workflows/macos.yml`) builds ad-hoc only.

## Microsoft Store

The Microsoft Store version of the Windows viewer is signed by Microsoft through the Store. A release can also carry `Jerislink-X.Y.Z-windows-x64-store-signed.msix`: a copy of that same Microsoft-signed package, which `.github/workflows/store-msix-to-release.yml` downloads from the Store and checks before attaching it. JerisHQ does not sign it and never submits it to SignPath. This policy, and the planned SignPath signing, cover only the viewer `Jerislink.exe` and the installer `setup.exe` built by `.github/workflows/release.yml`.
