#!/bin/zsh
APP="$HOME/Applications/JerisLink Host.app"
EXE="$APP/Contents/MacOS/JerisLinkHost"
LOG="/tmp/jerislink-video-watchdog.log"
RUNLOG="/tmp/jerislink-host.log"
TS="/usr/local/bin/tailscale"
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
SETTINGS="$HOME/Library/Application Support/JerisLink/video-settings.plist"
waiting_logged=0

if [[ ! -x "$TS" ]]; then
    TS="/Applications/Tailscale.app/Contents/MacOS/Tailscale"
fi

tailscale_ready() {
    local backend
    backend="$("$TS" status --json 2>/dev/null | /usr/bin/plutil -extract BackendState raw -o - - 2>/dev/null || true)"
    [[ "$backend" == "Running" ]] || return 1
    "$TS" ip -4 2>/dev/null | /usr/bin/grep -Fxq "$TARGET_IP"
}

video_setting() {
    local key="$1"
    local fallback="$2"
    if [[ -f "$SETTINGS" ]]; then
        local value
        value="$(/usr/bin/plutil -extract "$key" raw -o - "$SETTINGS" 2>/dev/null || true)"
        [[ -n "$value" ]] && { print -r -- "$value"; return; }
    fi
    print -r -- "$fallback"
}

while true; do
    if [[ -z "$TARGET_IP" || -z "$CLIENT_IP" ]]; then
        if [[ "$waiting_logged" -eq 0 ]]; then
            print -r -- "$(/bin/date '+%Y-%m-%d %H:%M:%S') not configured: set JERISLINK_BIND_IP and JERISLINK_CLIENT_IP in $CONF" >> "$LOG"
            waiting_logged=1
        fi
        /bin/sleep 5
        load_network_conf
        continue
    fi
    if /usr/bin/pgrep -f "^$EXE --duration 86400( |$)" >/dev/null 2>&1; then
        /bin/sleep 2
        continue
    fi
    if [[ ! -x "$TS" ]] || ! tailscale_ready; then
        if [[ "$waiting_logged" -eq 0 ]]; then
            print -r -- "$(/bin/date '+%Y-%m-%d %H:%M:%S') waiting for Tailscale Running + $TARGET_IP before launching JerisLink Host" >> "$LOG"
            waiting_logged=1
        fi
        /bin/sleep 1
        continue
    fi
    if [[ "$waiting_logged" -ne 0 ]]; then
        print -r -- "$(/bin/date '+%Y-%m-%d %H:%M:%S') Tailscale $TARGET_IP ready" >> "$LOG"
        waiting_logged=0
    fi
    codec="$(video_setting codec h264)"
    bitrate="$(video_setting bitrateMbps 25)"
    [[ "$codec" == "h264" || "$codec" == "hevc" ]] || codec="h264"
    [[ "$bitrate" == <-> && "$bitrate" -ge 4 && "$bitrate" -le 100 ]] || bitrate=25
    print -r -- "$(/bin/date '+%Y-%m-%d %H:%M:%S') JerisLink Host missing; launching executable codec=$codec bitrate=$bitrate Mbps" >> "$LOG"
    "$EXE" \
        --duration 86400 \
        --fps 60 --bitrate-mbps "$bitrate" \
        --codec "$codec" --range full --keyframe-interval 60 \
        --h264-profile constrained-high --capture-queue-depth 2 \
        --bind-ip "$TARGET_IP" --client-ip "$CLIENT_IP" --client-port 38402 \
        --packet-bytes 1200 --mouse-udp-port 38412 \
        --no-control-server --hide-cursor --output /dev/null >> "$RUNLOG" 2>&1 &
    /bin/sleep 1
done
