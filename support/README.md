# JerisLink Support

One-time remote-support product in the JerisLink family.

## Current phase

QS-TC0 transport acceptance is complete. QS-TC1 is now in progress: build the one-time support-session lifecycle around the accepted Tailcat/JerisLink transport path.

QS-TC1 now has five working vertical slices. P0 provides the one-time Session Broker, P1 adds the host-side Support Agent lifecycle owner, P2 adds the signed macOS AppKit Support Agent UI with post-approval JerisLink Host gating, P3 adds the supporter/controller flow that claims a six-digit code and launches the accepted Tailcat client + Windows Viewer after approval, and P4 hardens the broker with bounded per-client/global anonymous rate limits, trusted-proxy client-IP handling, live-session capacity, terminal-record retention/pruning, and loopback-only protection when trusting a proxy header. The broker still defaults to loopback and still requires an external HTTPS/edge abuse-protection deployment boundary before public use.

## Repository boundary

This repository owns Support-specific transport, session, broker, packaging and test code. It must not fork or duplicate JerisLink core capture/codec/input logic from `../personal` (the JerisLink core).

## Layout

- `cmd/jeris-support-transport/` - accepted Tailcat localhost bridge
- `cmd/jeris-session-broker/` - QS-TC1 short-code broker process
- `cmd/jeris-support-agent/` - QS-TC1 Support Agent CLI lifecycle prototype
- `cmd/jeris-support-controller/` - supporter-side short-code controller prototype
- `internal/sessionbroker/` - one-time session state machine and HTTP API
- `internal/brokerclient/` - authenticated host-side broker client
- `internal/supportagent/` - host-side ephemeral Tailcat child-process ownership
- `internal/supportcontroller/` - supporter-side Tailcat client and Viewer process ownership
- `agent/macos/` - signed macOS AppKit Support Agent GUI, runtime orchestration, and build packaging
- `agent/windows/` - Windows Support Agent / Windows Host integration (priority track)
- `relay/` - DERP/relay configuration (QS-TC2)
- `tests/` - transport and integration tests
