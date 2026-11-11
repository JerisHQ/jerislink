#!/bin/zsh
set -euo pipefail

APP="$HOME/Applications/JerisLink Host.app"
EXE="$APP/Contents/MacOS/JerisLinkHost"
WATCHDOG_PLIST="$HOME/Library/LaunchAgents/org.jeris.jerislink.video-watchdog.plist"
WATCHDOG_LABEL="org.jeris.jerislink.video-watchdog"
DOMAIN="gui/$(id -u)"
LOG="/tmp/jerislink-quality-ab.log"
RUNLOG="/tmp/jerislink-quality-ab-host.log"
CONF="${JERISLINK_NETWORK_CONF:-$HOME/Library/Application Support/JerisLink/network.conf}"
# network.conf is a zsh file with two lines, for example:
#   JERISLINK_BIND_IP=100.x.y.z     # this Mac's Tailscale IPv4
#   JERISLINK_CLIENT_IP=100.a.b.c   # the Windows viewer's Tailscale IPv4
load_network_conf() {
    [[ -f "$CONF" ]] && source "$CONF"
    TARGET_IP="${JERISLINK_BIND_IP:-}"
    CLIENT_IP="${JERISLINK_CLIENT_IP:-}"
}
load_network_conf

usage() {
    cat <<'USAGE'
Usage: quality-ab.zsh 20|25|30|40|status|restore

20/25/30/40  Run JerisLink Host with the selected Mbps profile.
status       Show the active JerisLink Host command line and watchdog state.
restore      Stop the A/B host and restore the v0.0.7 production watchdog (25 Mbps).
USAGE
}

watchdog_loaded() {
    launchctl print "$DOMAIN/$WATCHDOG_LABEL" >/dev/null 2>&1
}

stop_watchdog() {
    if watchdog_loaded; then
        launchctl bootout "$DOMAIN/$WATCHDOG_LABEL"
    fi
}

stop_video_host() {
    pkill -f "^$EXE --duration 86400( |$)" >/dev/null 2>&1 || true
    sleep 1
}

start_profile() {
    local mbps="$1"
    if [[ -z "$TARGET_IP" || -z "$CLIENT_IP" ]]; then
        print -u2 -- "Set JERISLINK_BIND_IP and JERISLINK_CLIENT_IP (env or $CONF)"
        return 1
    fi
    stop_watchdog
    stop_video_host

    print -r -- "$(date '+%Y-%m-%d %H:%M:%S') profile=${mbps}Mbps" >> "$LOG"
    "$EXE" \
        --duration 86400 \
        --width 3712 --height 2088 --fps 60 --bitrate-mbps "$mbps" \
        --codec h264 --range full --keyframe-interval 60 \
        --h264-profile constrained-high --capture-queue-depth 2 \
        --bind-ip "$TARGET_IP" --client-ip "$CLIENT_IP" --client-port 38402 \
        --packet-bytes 1200 --mouse-udp-port 38412 \
        --no-control-server --hide-cursor --output /dev/null >> "$RUNLOG" 2>&1 &

    sleep 3
    if ! pgrep -f "^$EXE --duration 86400.*--bitrate-mbps $mbps( |$)" >/dev/null 2>&1; then
        print -u2 -- "Failed to start ${mbps} Mbps profile"
        return 1
    fi
    print -r -- "ACTIVE_PROFILE=${mbps}Mbps"
    pgrep -fl "^$EXE --duration 86400( |$)" || true
}

restore_production() {
    stop_video_host
    if ! watchdog_loaded; then
        launchctl bootstrap "$DOMAIN" "$WATCHDOG_PLIST"
    fi
    launchctl kickstart -k "$DOMAIN/$WATCHDOG_LABEL" >/dev/null 2>&1 || true
    sleep 7
    print -r -- "PRODUCTION_RESTORED"
    pgrep -fl "^$EXE --duration 86400( |$)" || true
}

show_status() {
    if watchdog_loaded; then
        print -r -- "WATCHDOG=loaded"
    else
        print -r -- "WATCHDOG=unloaded"
    fi
    pgrep -fl "^$EXE --duration 86400( |$)" || print -r -- "VIDEO_HOST=not_running"
}

case "${1:-}" in
    20|25|30|40) start_profile "$1" ;;
    status) show_status ;;
    restore) restore_production ;;
    *) usage; exit 2 ;;
esac
