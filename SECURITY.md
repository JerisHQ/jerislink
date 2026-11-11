# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability** (GitHub private vulnerability reporting). Do not open a public issue.

Include the affected component (`personal/mac-host`, `personal/windows-client` or `support/`), the version or commit, and steps to reproduce. We aim to acknowledge reports within 7 days.

## Supported versions

Only the latest release and the `main` branch receive security fixes.

## Known security boundaries

- JerisLink is experimental and has not had an independent security audit.
- The viewer-host control channel trusts the Tailscale network path between the two machines. Restrict who can reach the host with Tailscale ACLs.
- The macOS input helper needs the Accessibility permission to inject keyboard and mouse events. Grant it only to builds you trust.
- The Support session broker (`support/cmd/jeris-session-broker`) listens on loopback by default. Before exposing it to the internet, put it behind an HTTPS reverse proxy with abuse protection, and only enable trusted-proxy headers for that proxy.
- `support/cmd/qs-tc0-smoke` contains a fixed test control token. It is a local smoke-test tool, not for production use.
