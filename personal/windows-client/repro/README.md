# Host-events repro

Checks that the viewer survives the host restarting, pausing, switching codec
and changing resolution, and that video comes back by itself.

It uses a private, short-lived `JerisLinkHost` on the Mac that streams only to
the test PC. The installed host agents, `network.conf` and
`video-settings.plist` are not touched, so a viewer already connected to the
Mac keeps working. The viewer runs with `--no-control`, so it never changes
host settings either.

1. On the Windows PC (interactive session), start the viewer:

       powershell -ExecutionPolicy Bypass -File repro-viewer.ps1 -exe <path>\Jerislink.exe -tag try1 -secs 100

2. Within a few seconds, on the Mac:

       ./repro-host-events.sh <windows-tailnet-ip>

   Phases: h264 12 s, 12 s silence, h264 10 s, hevc 10 s, h264 10 s,
   h264 1280x720 10 s, h264 1920x1080 10 s. `JERISLINK_REPRO_GAP=0` skips the
   silence.

3. Pass: `repro-result-try1.txt` says `alive_at_end=True`, and
   `repro-viewer-try1.log` shows `stream.idle`, `stream.resumed`,
   `stream.codec_change` and `cpu.source_resized` (or `input.remote_size=`)
   with frames decoded after each one. A PC without an HEVC decoder logs
   `video.rebuild_failed` for the hevc phase, keeps the window open, and
   recovers when h264 returns.
