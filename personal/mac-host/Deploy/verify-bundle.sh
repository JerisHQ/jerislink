#!/bin/zsh
# Checks a built JerisLink.app: layout, bundle identifiers, LaunchAgent targets,
# code signature, and that both executables start from inside the bundle.
# Usage: verify-bundle.sh <path/to/JerisLink.app>
set -euo pipefail
APP="${1:?usage: verify-bundle.sh <JerisLink.app>}"
HELPER="$APP/Contents/Helpers/JerisLink Input Helper.app"
SEND="$APP/Contents/Library/Helpers/JerisLink Send.app"
SERVICE="$APP/Contents/Library/Helpers/JerisLink Service.app"
fail() { print -u2 -- "FAIL: $*"; exit 1; }
ok() { print -- "ok: $*"; }

plist_value() { /usr/libexec/PlistBuddy -c "Print :$2" "$1" 2>/dev/null; }

[[ -x "$APP/Contents/MacOS/JerisLinkHost" ]] || fail "missing host executable"
[[ -x "$HELPER/Contents/MacOS/JerisLinkInputHelper" ]] || fail "missing input helper executable"
[[ -x "$SEND/Contents/MacOS/JerisLinkSend" ]] || fail "missing send helper executable"
[[ -x "$SERVICE/Contents/MacOS/JerisLinkHost" ]] || fail "missing service helper executable"
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
# Same bundle id as the app on purpose: Screen Recording and defaults follow it.
[[ "$(plist_value "$SERVICE/Contents/Info.plist" CFBundleIdentifier)" == "org.jeris.jerislink.host" ]] || fail "service helper bundle id"
[[ "$(plist_value "$SERVICE/Contents/Info.plist" LSUIElement)" == "true" ]] || fail "service helper LSUIElement"
[[ "$(plist_value "$SERVICE/Contents/Info.plist" JLBuildSHA)" == "$(plist_value "$APP/Contents/Info.plist" JLBuildSHA)" ]] || fail "service helper build sha"
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
    # Video and control must not run from JerisLink.app's own path (see build-apps.sh).
    if [[ "$label" != org.jeris.jerislink.agent.input-helper ]]; then
        [[ "$program" == "Contents/Library/Helpers/JerisLink Service.app/Contents/MacOS/JerisLinkHost" ]] || fail "$label must run from JerisLink Service.app"
    fi
    ok "$label -> $program"
done
[[ "$(ls "$APP/Contents/Library/LaunchAgents" | wc -l | tr -d ' ')" == "${#labels}" ]] || fail "unexpected LaunchAgents"

/usr/bin/codesign --verify --strict --deep --verbose=2 "$APP"
for target in "$HELPER" "$SEND" "$SERVICE" "$APP"; do
    flags="$(/usr/bin/codesign -dv "$target" 2>&1 | /usr/bin/grep -E '^CodeDirectory' || true)"
    [[ "$flags" == *"runtime"* ]] || fail "hardened runtime not enabled on $target"
done
/usr/bin/codesign --verify --strict --verbose=2 "$SEND"
[[ "$(/usr/bin/codesign -dv "$SEND" 2>&1 | /usr/bin/sed -n "s/^Identifier=//p")" == "org.jeris.jerislink.send" ]] || fail "send helper signing identifier"
/usr/bin/codesign --verify --strict --verbose=2 "$SERVICE"
[[ "$(/usr/bin/codesign -dv "$SERVICE" 2>&1 | /usr/bin/sed -n "s/^Identifier=//p")" == "org.jeris.jerislink.host" ]] || fail "service helper signing identifier"
if [[ "$(/usr/bin/codesign -dv "$APP" 2>&1 | /usr/bin/sed -n "s/^Signature=//p")" != "adhoc" ]]; then
    # Signed builds: the helper must satisfy the same designated requirement as
    # the app, or Screen Recording would not carry over. Ad-hoc DRs are cdhashes.
    [[ "$(/usr/bin/codesign -d -r- "$SERVICE" 2>&1 | /usr/bin/grep '^designated')" == "$(/usr/bin/codesign -d -r- "$APP" 2>&1 | /usr/bin/grep '^designated')" ]] || fail "service helper designated requirement differs from the app"
    ok "service helper designated requirement matches the app"
fi
ok "code signature valid, hardened runtime on app and all helpers"

host_version="$("$APP/Contents/MacOS/JerisLinkHost" --version)"
service_version="$("$SERVICE/Contents/MacOS/JerisLinkHost" --version)"
helper_version="$("$HELPER/Contents/MacOS/JerisLinkInputHelper" --version)"
send_version="$("$SEND/Contents/MacOS/JerisLinkSend" --version)"
expected="$(plist_value "$APP/Contents/Info.plist" CFBundleShortVersionString)"
[[ "$host_version" == "JerisLink Host v$expected" ]] || fail "host reported '$host_version'"
[[ "$service_version" == "JerisLink Host v$expected" ]] || fail "service helper reported '$service_version'"
[[ "$helper_version" == "JerisLink Input Helper v$expected" ]] || fail "helper reported '$helper_version'"
[[ "$send_version" == "JerisLink Send v$expected" ]] || fail "send helper reported '$send_version'"
ok "$host_version"
ok "$helper_version"
ok "$send_version"

"$APP/Contents/MacOS/JerisLinkHost" --status
if "$SERVICE/Contents/MacOS/JerisLinkHost" --status >/dev/null 2>&1; then fail "service helper accepted --status"; fi
ok "service helper refuses agent commands"
ok "bundle verified: $APP"
