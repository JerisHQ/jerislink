# JerisLink macOS production deployment

The macOS host ships as one app, `JerisLink.app`:

```
JerisLink.app/
  Contents/
    MacOS/JerisLinkHost                     host: video, control service, launcher
    Helpers/JerisLink Input Helper.app/     input injection helper (own process, own bundle id)
    Library/LaunchAgents/                   three agents registered with SMAppService
      org.jeris.jerislink.agent.input-helper.plist
      org.jeris.jerislink.agent.control.plist
      org.jeris.jerislink.agent.video.plist
```

The Input Helper stays a separate process with its own bundle identifier. If it crashes, the host and the video stream keep running, and the other way round. launchd restarts whichever process exits (`KeepAlive`).

## Background agents

The app registers its agents itself with `SMAppService` (macOS 13+; the app requires macOS 14). There are no hand-installed `~/Library/LaunchAgents` files and no zsh watchdogs.

| Agent label | Runs | Replaces |
|---|---|---|
| `org.jeris.jerislink.agent.input-helper` | `Contents/Helpers/JerisLink Input Helper.app/Contents/MacOS/JerisLinkInputHelper` | `input-helper-watchdog.zsh` + `org.jeris.jerislink.input-helper-watchdog` |
| `org.jeris.jerislink.agent.control` | `JerisLinkHost --control-only --bind-ip 127.0.0.1 --control-port 38411 --control-client-ip 127.0.0.1 --control-inject` | `org.jeris.jerislink.control` |
| `org.jeris.jerislink.agent.video` | `JerisLinkHost --service video` | `video-watchdog.zsh` + `org.jeris.jerislink.video-watchdog` |

`JerisLinkHost --service video` does what the video watchdog did: it reads `JERISLINK_BIND_IP` and `JERISLINK_CLIENT_IP` from `~/Library/Application Support/JerisLink/network.conf` (or the environment), waits until the bind address is up on a local interface, reads the persisted codec/bitrate from `video-settings.plist`, and runs the video host. When the control service changes codec or bitrate it restarts the video agent with `launchctl kickstart -k`.

Host commands:

```sh
JerisLink.app/Contents/MacOS/JerisLinkHost --register    # register the three agents
JerisLink.app/Contents/MacOS/JerisLinkHost --unregister  # unregister them
JerisLink.app/Contents/MacOS/JerisLinkHost --status      # show each agent's status
JerisLink.app/Contents/MacOS/JerisLinkHost --version
```

Opening `JerisLink.app` from Finder (no arguments) does the same as `--register`, asks for Screen Recording, and shows the agent status with a button to the right System Settings page.

## Ports (unchanged)

- control endpoint 38400 (Tailscale proxy) -> localhost 38411
- input helper localhost 38410
- video UDP 38402
- mouse/cursor-state UDP side-channel 38412

The Windows viewer and the wire protocol are unchanged.

## Privacy permissions (TCC)

Each permission belongs to the identity of the process that uses it:

| Permission | Who asks | Identity the user approves | When |
|---|---|---|---|
| Screen Recording | `JerisLinkHost` (video agent and launcher) | **JerisLink** (`org.jeris.jerislink.host`) | First time `JerisLink.app` is opened |
| Accessibility | `JerisLinkInputHelper` (input-helper agent) | **JerisLink Input Helper** (`org.jeris.jerislink.inputhelper`) | First time the helper starts after install |
| Login Items / background items | macOS | **JerisLink** | After registration, if `--status` shows `requiresApproval` |

First install on a Mac:

1. Install `JerisLink.app` into `~/Applications` (see below) and open it once.
2. Allow **JerisLink** under System Settings > Privacy & Security > Screen Recording.
3. Allow **JerisLink Input Helper** under System Settings > Privacy & Security > Accessibility.
4. If the app reports `requiresApproval`, turn JerisLink on under System Settings > General > Login Items & Extensions.
5. Run `JerisLinkHost --status`; all three agents should be `enabled`.

TCC records are tied to the code signature. Rebuilds signed with the same certificate and bundle identifiers keep their approvals. Switching certificates (for example from `JerisLink Local Code Signing` to Developer ID) needs the approvals again. See `SIGNING.md`.

## Paths

- App: `~/Applications/JerisLink.app`
- Support: `~/Library/Application Support/JerisLink/` (`network.conf`, `video-settings.plist`)
- Logs: `/tmp/jerislink-host.{log,err}`, `/tmp/jerislink-control-service.{log,err}`, `/tmp/jerislink-input-helper.{log,err}`

## Build

```sh
cd personal/mac-host
./Deploy/setup-local-signing.sh      # once per Mac, for the stable local identity
./Deploy/build-apps.sh [out-dir]     # default out-dir: .dist
./Deploy/verify-bundle.sh .dist/JerisLink.app
```

`verify-bundle.sh` checks the layout, bundle identifiers, the three agent plists and their targets, the code signature, hardened runtime, and that both executables start from inside the bundle. CI runs the same two scripts with ad-hoc signing.

Signing modes, Developer ID and notarization: see `SIGNING.md`.

## Install or upgrade

```sh
cd personal/mac-host
./Deploy/install-production.sh                      # build, then install
./Deploy/install-production.sh /path/JerisLink.app   # install a downloaded build
```

Migration from the old layout (two apps, three hand-installed LaunchAgents, zsh watchdogs) is done by the script:

- boots out and deletes `org.jeris.jerislink.control`, `org.jeris.jerislink.input-helper-watchdog` and `org.jeris.jerislink.video-watchdog` from `~/Library/LaunchAgents`,
- stops and deletes `~/Applications/JerisLink Host.app`, `~/Applications/JerisLink Input Helper.app` and `~/Library/Application Support/JerisLink/bin`,
- keeps `network.conf` and `video-settings.plist`,
- copies the new app to `~/Applications/JerisLink.app` and registers its agents.

TCC matches an app by bundle identifier and designated requirement (which includes the signing certificate), so approvals carry over only if the new app is signed with the same certificate as the installed one. Compare before migrating:

```sh
codesign -d -r- ~/Applications/"JerisLink Host.app"
codesign -d -r- ~/Applications/JerisLink.app
```

Whatever the result, check the Screen Recording, Accessibility and Login Items entries once after migration (steps 2-5 above): the app path, name and parent process all change.

## Host baseline

- active main display native framebuffer resolution @ 60 fps (auto-detected); `--width` / `--height` remain debug overrides
- display mode changes restart capture/encoder at the new native size
- H.264 or HEVC, 4:2:0 Full Range; H.264 / 25 Mbps is the default
- client-selected codec/bitrate are persisted in `video-settings.plist` and read each time the video agent starts
- keyframe interval 60 with on-demand IDR recovery
- ScreenCaptureKit queue depth 2
- captured macOS cursor hidden; Windows renders the local cursor
- TCP control/helper sockets suppress SIGPIPE
