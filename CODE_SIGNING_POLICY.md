# Code signing policy

Status: planned. Windows binaries are not signed yet.

Free code signing for Windows is planned through [SignPath.io](https://about.signpath.io), with a certificate from the [SignPath Foundation](https://signpath.org). Once active, signed releases will state: "Free code signing provided by SignPath.io, certificate by SignPath Foundation".

## What gets signed

- Only Windows binaries built by this repository's GitHub Actions workflow (`.github/workflows/windows.yml`) on GitHub-hosted runners, from a tagged commit on `main`.
- Binaries built anywhere else, including developers' own machines, are never submitted for signing.

## Roles

| Role | Who |
|---|---|
| Committers and reviewers | Members of the JerisHQ GitHub organization with write access |
| Approvers (approve each signing request) | The JerisHQ organization owners |

All maintainers use multi-factor authentication on GitHub and SignPath.

## Privacy

JerisLink connects only to the peer machine you configure (over your own Tailscale tailnet). It does not send telemetry or any other data to servers operated by the JerisLink project. The optional Support component talks to a session broker that you host yourself.

## macOS

macOS builds are not covered by this policy. CI produces unsigned (ad-hoc) macOS builds; Developer ID signing and notarization are done by a maintainer on their own machine.
