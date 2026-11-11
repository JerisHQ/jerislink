# QS-TC0 - Tailcat Transport Adapter

Goal: run existing JerisLink traffic through Tailcat while keeping JerisLink production unchanged.

Logical Tailcat ports:

- TCP 38400: reliable JerisLink control
- UDP 38402: video datagrams, Mac -> Windows
- UDP 38412: mouse/cursor side-channel, bidirectional

PoC localhost ports are intentionally separate from production:

Mac test process:
- video destination: 127.0.0.1:48402
- control server: 127.0.0.1:48411
- mouse server: 127.0.0.1:48412

Windows test Viewer:
- video listen: 127.0.0.1:48402
- control destination: 127.0.0.1:48400
- mouse destination: 127.0.0.1:48412

The Support transport helper maps those localhost endpoints to Tailcat logical ports without changing the JerisLink wire protocol.
