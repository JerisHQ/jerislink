#!/bin/zsh
# Checks a built JerisLink.app: layout, bundle identifiers, LaunchAgent targets,
# code signature, and that both executables start from inside the bundle.
# Usage: verify-bundle.sh <path/to/JerisLink.app>
set -euo pipefail
APP="${1:?usage: verify-bundle.sh <JerisLink.app>}"
HELPER="$APP/Contents/Helpers/JerisLink Input Helper.app"
fail() { print -u2 -- "FAIL: $*"; exit 1; }
ok() { print -- "ok: $*"; }

plist_value() { /usr/libexec/PlistBuddy -c "Print :$2" "$1" 2>/dev/null; }

[[ -x "$APP/Contents/MacOS/JerisLinkHost" ]] || fail "missing host executable"
[[ -x "$HELPER/Contents/MacOS/JerisLinkInputHelper" ]] || fail "missing input helper executable"
ok "executables present"

[[ "$(plist_value "$APP/Contents/Info.plist" CFBundleIdentifier)" == "org.jeris.jerislink.host" ]] || fail "app bundle id"
[[ "$(plist_value "$HELPER/Contents/Info.plist" CFBundleIdentifier)" == "org.jeris.jerislink.inputhelper" ]] || fail "helper bundle id"
[[ "$(plist_value "$APP/Contents/Info.plist" CFBundleName)" == "JerisLink" ]] || fail "app name"
ok "bundle identifiers"

typeset -a labels
labels=(org.jeris.jerislink.agent.input-helper org.jeris.jerislink.agent.control org.jeris.jerislink.agent.video)
for label in "${labels[@]}"; do
    agent="$APP/Contents/Library/LaunchAgents/$label.plist"
    [[ -f "$agent" ]] || fail "missing $agent"
    /usr/bin/plutil -lint "$agent" >/dev/null || fail "lint $agent"
    [[ "$(plist_value "$agent" Label)" == "$label" ]] || fail "label in $agent"
    program="$(plist_value "$agent" BundleProgram)"
    [[ -x "$APP/$program" ]] || fail "$label BundleProgram not executable: $program"
    [[ "$(plist_value "$agent" KeepAlive)" == "true" ]] || fail "$label KeepAlive"
    ok "$label -> $program"
done
[[ "$(ls "$APP/Contents/Library/LaunchAgents" | wc -l | tr -d ' ')" == "${#labels}" ]] || fail "unexpected LaunchAgents"

/usr/bin/codesign --verify --strict --deep --verbose=2 "$APP"
for target in "$HELPER" "$APP"; do
    flags="$(/usr/bin/codesign -dv "$target" 2>&1 | /usr/bin/grep -E '^CodeDirectory' || true)"
    [[ "$flags" == *"runtime"* ]] || fail "hardened runtime not enabled on $target"
done
ok "code signature valid, hardened runtime on app and helper"

host_version="$("$APP/Contents/MacOS/JerisLinkHost" --version)"
helper_version="$("$HELPER/Contents/MacOS/JerisLinkInputHelper" --version)"
expected="$(plist_value "$APP/Contents/Info.plist" CFBundleShortVersionString)"
[[ "$host_version" == "JerisLink Host v$expected" ]] || fail "host reported '$host_version'"
[[ "$helper_version" == "JerisLink Input Helper v$expected" ]] || fail "helper reported '$helper_version'"
ok "$host_version"
ok "$helper_version"

"$APP/Contents/MacOS/JerisLinkHost" --status
ok "bundle verified: $APP"
