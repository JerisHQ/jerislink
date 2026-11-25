# JerisLink macOS production deployment

The macOS host ships as one app, `JerisLink.app`:

```
JerisLink.app/
  Contents/
    MacOS/JerisLinkHost                     launcher and command line
    Helpers/JerisLink Input Helper.app/     input injection helper (own process, own bundle id)
    Library/Helpers/JerisLink Service.app/  same host binary and bundle id: runs the video and control agents
    Library/Helpers/JerisLink Send.app/     Finder Service "Send to JerisLink"
    Library/LaunchAgents/                   three agents registered with SMAppService
      org.jeris.jerislink.agent.input-helper.plist
      org.jeris.jerislink.agent.control.plist
      org.jeris.jerislink.agent.video.plist
```

The Input Helper stays a separate process with its own bundle identifier. If it crashes, the host and the video stream keep running, and the other way round. launchd restarts whichever process exits (`KeepAlive`).

## Install from a release

For people who use JerisLink, not build it. The Windows viewer is JerisLink from the Microsoft Store (or the installer on the GitHub release). JerisLink works only between devices in the same Tailscale network (tailnet). It does not connect over the open internet or a LAN.

You need a Mac with Apple silicon and macOS 14 or later, and Tailscale signed in to the same tailnet on the Mac and the Windows PC. Note each machine's Tailscale IPv4 address (`100.x.y.z`).

1. From <https://github.com/JerisHQ/jerislink/releases>, download `JerisLink-<version>-macos-arm64.zip`. Do not use a file ending in `-unsigned.zip`; that one is ad-hoc signed for developers. The normal zip is Developer ID signed and notarized by Apple.
2. Unpack it and move `JerisLink.app` into `~/Applications` (the `Applications` folder in your home folder; create it if it is missing).
3. Open `JerisLink.app` once. It registers its background services and shows their status.
4. Allow the permissions macOS asks for (see "Privacy permissions" below):
   - Screen Recording (shown as **JerisLink**): screen video and the Mac's sound.
   - Accessibility (shown as **JerisLink Input Helper**): keyboard and mouse from the PC.
   - Downloads folder (shown as **JerisLink**, asked the first time the PC sends a file): files go to `~/Downloads/JerisLink`. If you refuse, they go to `~/JerisLink Received`.
   - Login Items, only if the status shows `requiresApproval`.

   Then open `JerisLink.app` again. All three services should show `enabled`.
5. Create the settings file `listen.plist` once in Terminal (see "Listen endpoint" below). The app does not create it yet, and its **連線設定…** window has no setting for the listen mode:

   ```sh
   mkdir -p ~/Library/Application\ Support/JerisLink
   cd ~/Library/Application\ Support/JerisLink
   /usr/bin/lockf -k listen.plist.lock /usr/libexec/PlistBuddy \
     -c 'Add :mode string tailnet' listen.plist
   ```

   The host does not listen yet: it waits for a password or an allowed address. Always edit `listen.plist` through `lockf` like this.
6. Set a connection password: open `JerisLink.app`, click **連線設定…** (connection settings), type the password twice and click **設定／更改密碼**. It needs at least 10 characters, with an upper-case letter, a lower-case letter and a symbol. The services pick it up within a few seconds; no restart is needed. From then on, any device in your tailnet that can reach the Mac connects with the password (Tailscale's access controls decide which devices can reach it).

   Optional: to allow only some PCs, put their Tailscale IPv4 addresses in **白名單** (allowed addresses) in the same window and click **儲存白名單**. Blocked addresses (**黑名單**) and the password are changed there too. An older setup with the PC's address in `clientIP` keeps working without a password; saving a whitelist in 連線設定 replaces `clientIP`.
7. On the PC, open JerisLink, type the **Mac's** Tailscale IPv4 and the password on the launch screen, and connect. This PC's address is chosen automatically; both addresses are shown read-only under Connection info.

The Microsoft Store version of the viewer (v0.4.1 and later) has its own "Send to JerisLink" command in the Explorer right-click menu (Windows 11: in the first menu). If the entry does not appear, drag files onto the viewer window or its Files panel instead.

To remove the host: run `~/Applications/JerisLink.app/Contents/MacOS/JerisLinkHost --unregister`, delete `~/Applications/JerisLink.app` and `~/Library/Application Support/JerisLink`, then remove JerisLink from Screen Recording and Accessibility in System Settings.

## Background agents

The app registers its agents itself with `SMAppService` (macOS 13+; the app requires macOS 14). There are no hand-installed `~/Library/LaunchAgents` files and no zsh watchdogs.

| Agent label | Runs | Replaces |
|---|---|---|
| `org.jeris.jerislink.agent.input-helper` | `Contents/Helpers/JerisLink Input Helper.app/Contents/MacOS/JerisLinkInputHelper` | `input-helper-watchdog.zsh` + `org.jeris.jerislink.input-helper-watchdog` |
| `org.jeris.jerislink.agent.control` | `JerisLink Service.app/.../JerisLinkHost --service control --control-inject` | `org.jeris.jerislink.control` |
| `org.jeris.jerislink.agent.video` | `JerisLink Service.app/.../JerisLinkHost --service video` | `video-watchdog.zsh` + `org.jeris.jerislink.video-watchdog` |

`JerisLinkHost --service video` does what the video watchdog did: it takes its addresses from the listen endpoint (see "Listen endpoint" below), waits until the bind address is up on this Mac, reads codec, bitrate, `fps` (30 or 60) and `keepDisplayAwake` from `video-settings.plist`, and runs the video host. At 60 fps it uses ScreenCaptureKit queue depth 5, at 30 fps depth 2. With `keepDisplayAwake` true it holds a display-sleep assertion while it runs. `JerisLinkHost --video-config` prints what it will use. When the control service changes codec or bitrate it restarts the video agent with `launchctl kickstart -k`.

Host commands:

```sh
JerisLink.app/Contents/MacOS/JerisLinkHost --register    # register the three agents
JerisLink.app/Contents/MacOS/JerisLinkHost --unregister  # unregister them
JerisLink.app/Contents/MacOS/JerisLinkHost --status      # show each agent's status
JerisLink.app/Contents/MacOS/JerisLinkHost --version
```

Opening `JerisLink.app` from Finder, Spotlight or the Dock (no arguments) does the same as `--register`, asks for Screen Recording, and shows the agent status with a button to the right System Settings page. This also works while the services run.

Why the video and control agents run from `JerisLink Service.app`: ScreenCaptureKit and the Accessibility calls check those processes in with Launch Services as background apps that never answer an open request. Launch Services matches a running app by its bundle path. When the agents ran from `JerisLink.app` itself, opening the app was routed to them and macOS showed "The application “JerisLink” is not open anymore." `JerisLink Service.app` is a copy of the same binary with the same bundle id and signature, so Screen Recording and the defaults domain stay the same; only the path differs. Opening `JerisLink Service.app` directly opens `JerisLink.app`. Its `--register`, `--unregister` and `--status` refuse to run; use `JerisLink.app/Contents/MacOS/JerisLinkHost`.

After installing a build that moves the agents (or back), run `--unregister` then `--register` so launchd picks up the new program path.

## Listen endpoint

Video, mouse UDP and control all use one endpoint, so the screen and the input always listen on the same interface.

- `~/Library/Application Support/JerisLink/listen.plist`, when present, decides it:
  - `mode` = `tailnet`: bind this Mac's tailnet address (the `utun` IPv4 in 100.64.0.0/10, or `bindIP` if set). Who may connect:
    - `passwordSet` true (set by 連線設定; the key derived from the password is in the Keychain): every connection must pass the password check. With no `allowedIPs` (or an empty list), any address that reaches the listener may try; with `allowedIPs`, only those addresses.
    - No password: only the addresses in `allowedIPs`, with no password check, as in v0.3. A file from before v0.4.0 with only `clientIP` gets `allowedIPs` = [`clientIP`] when the control service starts, and that list follows `clientIP` until 連線設定 saves a whitelist.
    - Neither a password nor `allowedIPs` nor `clientIP`: not configured; the services do not listen. A `clientIP`, when set, must be in 100.64.0.0/10.
    - `blockedIPs` (連線設定's **黑名單**, and addresses blocked after repeated wrong passwords) are refused in every case.
    - Do not set `passwordSet` by hand: without the Keychain item the host refuses every viewer.
  - `mode` = `loopback`: bind and allow 127.0.0.1 only.
  - Any other mode (for example `lan`) is refused; the services log "not configured" and do not listen.
- Without listen.plist, `JERISLINK_BIND_IP` and `JERISLINK_CLIENT_IP` from `network.conf` (or the environment) are used as before.
- Interface gone, or the settings changed: both services stop within about 4 s, launchd starts them again, and they wait for the endpoint. They never fall back to another interface.
- Editing listen.plist: hold its lock, `/usr/bin/lockf -k listen.plist.lock <command>` in that folder, as in the install steps. The services take the same lock (an flock on `listen.plist.lock`) from read to replace when they write the blacklist or migrate the file, so no edit is lost. An edit made without the lock (a text editor, plain PlistBuddy) can race with a blacklist write and is not supported.
- A service that cannot take the lock within 0.5 s writes nothing. A new block then stays pending in `auth-state/pending-blocks.plist` and no viewer gets a challenge until it is saved. If that pending file exists but cannot be read, the control service admits no viewer at all until it reads again or is removed; it is never overwritten meanwhile.

After step 5 of the install the file holds only the mode; after a password and a whitelist are saved in 連線設定 it looks like this:

```xml
<dict>
  <key>mode</key><string>tailnet</string>
  <key>passwordSet</key><true/>
  <key>allowedIPs</key><array><string>100.64.0.20</string></array>
</dict>
```

## Ports

- control TCP 38400, bound directly on the endpoint address. Peers are admitted as described under "Listen endpoint" (blocked addresses, allowed addresses, password); a refused peer is logged (`Control reject peer=…` or `auth.…`) and closed. No `tailscale serve` forward is used.
- control relay localhost 38411 (`--relay-port`), for the video service's mouse relay only; accepts 127.0.0.1.
- input helper localhost 38410
- video UDP to port 38402 on the viewer, sent only to the viewer of the admitted control session
- mouse/cursor-state UDP side-channel 38412, on the endpoint address, only from the viewer of the admitted control session (with a password, each packet must also carry that session's key tag)

### Moving from the `tailscale serve` setup

Older builds ran control on 127.0.0.1:38411 behind `tailscale serve --tcp 38400 tcp://127.0.0.1:38411`, so every tailnet device could reach it. With this build, turn that forward off after installing, so 38400 reaches the host's own socket:

```sh
tailscale serve --tcp 38400 off
```

Until then the forward still delivers to the 38411 relay, which refuses it: the relay accepts only the video service's own mouse relay.

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
- Support: `~/Library/Application Support/JerisLink/` (`listen.plist`, `network.conf`, `video-settings.plist`)
- Logs: `/tmp/jerislink-host.{log,err}`, `/tmp/jerislink-control-service.{log,err}`, `/tmp/jerislink-input-helper.{log,err}`
- Debug mode is off by default. With `JERISLINK_DEBUG=1` the input helper also logs one line per injected mouse button (time, button, down/up, modifier flags, click state; never key codes) to `/tmp/jerislink-input-helper.err`. To turn it on for one session: `launchctl setenv JERISLINK_DEBUG 1` and `launchctl kickstart -k gui/$(id -u)/org.jeris.jerislink.agent.input-helper`. To turn it off: `launchctl unsetenv JERISLINK_DEBUG` and kick the agent again.

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

- active main display native framebuffer resolution @ 60 fps (auto-detected), scaled down with its aspect ratio kept when larger than 3840×2160 pixels of area (`--max-encode-pixels` changes the cap); `--width` / `--height` remain debug overrides
- display mode changes restart capture/encoder at the new native size
- H.264 or HEVC, 4:2:0 Full Range; H.264 / 25 Mbps is the default
- client-selected codec/bitrate are persisted in `video-settings.plist` and read each time the video agent starts
- keyframe interval 60 with on-demand IDR recovery
- ScreenCaptureKit queue depth 5 at 60 fps, 2 at 30 fps (`fps` in `video-settings.plist`, default 60)
- `keepDisplayAwake` in `video-settings.plist` keeps the display from idle sleep while the video agent runs
- captured macOS cursor hidden; Windows renders the local cursor
- TCP control/helper sockets suppress SIGPIPE
