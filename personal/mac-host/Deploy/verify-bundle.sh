#!/bin/zsh
# Checks a built JerisLink.app: layout, bundle identifiers, LaunchAgent targets,
# code signature, and that both executables start from inside the bundle.
# Usage: verify-bundle.sh <path/to/JerisLink.app>
set -euo pipefail
APP="${1:?usage: verify-bundle.sh <JerisLink.app>}"
HELPER="$APP/Contents/Helpers/JerisLink Input Helper.app"
SEND="$APP/Contents/Library/Helpers/JerisLink Send.app"
fail() { print -u2 -- "FAIL: $*"; exit 1; }
ok() { print -- "ok: $*"; }

plist_value() { /usr/libexec/PlistBuddy -c "Print :$2" "$1" 2>/dev/null; }

[[ -x "$APP/Contents/MacOS/JerisLinkHost" ]] || fail "missing host executable"
[[ -x "$HELPER/Contents/MacOS/JerisLinkInputHelper" ]] || fail "missing input helper executable"
[[ -x "$SEND/Contents/MacOS/JerisLinkSend" ]] || fail "missing send helper executable"
grep -q "Redistribution and use in source and binary forms" "$APP/Contents/Resources/COPYING-opus.txt" 2>/dev/null || fail "missing libopus licence (COPYING-opus.txt)"
ok "executables present"

[[ "$(plist_value "$APP/Contents/Info.plist" CFBundleIdentifier)" == "org.jeris.jerislink.host" ]] || fail "app bundle id"
[[ "$(plist_value "$HELPER/Contents/Info.plist" CFBundleIdentifier)" == "org.jeris.jerislink.inputhelper" ]] || fail "helper bundle id"
[[ "$(plist_value "$SEND/Contents/Info.plist" CFBundleIdentifier)" == "org.jeris.jerislink.send" ]] || fail "send helper bundle id"
[[ "$(plist_value "$SEND/Contents/Info.plist" LSUIElement)" == "true" ]] || fail "send helper LSUIElement"
[[ "$(plist_value "$SEND/Contents/Info.plist" NSServices:0:NSMessage)" == "sendToJerisLink" ]] || fail "send helper NSMessage"
[[ "$(plist_value "$SEND/Contents/Info.plist" NSServices:0:NSMenuItem:default)" == "Send to JerisLink" ]] || fail "send helper menu item"
[[ "$(plist_value "$SEND/Contents/Info.plist" NSServices:0:NSSendFileTypes:0)" == "public.item" ]] || fail "send helper file types"
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
for target in "$HELPER" "$SEND" "$APP"; do
    flags="$(/usr/bin/codesign -dv "$target" 2>&1 | /usr/bin/grep -E '^CodeDirectory' || true)"
    [[ "$flags" == *"runtime"* ]] || fail "hardened runtime not enabled on $target"
done
/usr/bin/codesign --verify --strict --verbose=2 "$SEND"
[[ "$(/usr/bin/codesign -dv "$SEND" 2>&1 | /usr/bin/sed -n "s/^Identifier=//p")" == "org.jeris.jerislink.send" ]] || fail "send helper signing identifier"
ok "code signature valid, hardened runtime on app and both helpers"

host_version="$("$APP/Contents/MacOS/JerisLinkHost" --version)"
helper_version="$("$HELPER/Contents/MacOS/JerisLinkInputHelper" --version)"
send_version="$("$SEND/Contents/MacOS/JerisLinkSend" --version)"
expected="$(plist_value "$APP/Contents/Info.plist" CFBundleShortVersionString)"
[[ "$host_version" == "JerisLink Host v$expected" ]] || fail "host reported '$host_version'"
[[ "$helper_version" == "JerisLink Input Helper v$expected" ]] || fail "helper reported '$helper_version'"
[[ "$send_version" == "JerisLink Send v$expected" ]] || fail "send helper reported '$send_version'"
ok "$host_version"
ok "$helper_version"
ok "$send_version"

"$APP/Contents/MacOS/JerisLinkHost" --status
ok "bundle verified: $APP"
