#!/bin/zsh
# Repro for "viewer exits/crashes when the host restarts, stops, or changes codec/size".
# Runs a private, short-lived JerisLinkHost that streams only to the test viewer.
# It does not touch the installed host agents, network.conf or video-settings.plist.
#
#   repro-host-events.sh <viewer-ip> [log-dir]
#
# Phases (one host process each, so every phase is a real host restart with
# frame ids starting again at 1):
#   1 h264 1920x1080 12s   -> baseline
#   gap 12s                -> host stops sending (longer than the 8s idle timeout)
#   2 h264 1920x1080 10s   -> host comes back
#   3 hevc 1920x1080 10s   -> codec switch h264 -> hevc
#   4 h264 1920x1080 10s   -> codec switch hevc -> h264
#   5 h264 1280x720  10s   -> resolution change
#   6 h264 1920x1080 10s   -> resolution change back
set -u
VIEWER_IP=${1:?viewer tailnet ip}
OUT=${2:-$PWD/repro-$(date -u +%Y%m%dT%H%M%SZ)}
HOST=${JERISLINK_HOST_BIN:-$HOME/Applications/JerisLink.app/Contents/MacOS/JerisLinkHost}
BIND=${JERISLINK_BIND_IP:-100.64.0.25}
DISPLAY_ID=${JERISLINK_DISPLAY_ID:-5}
mkdir -p "$OUT"
phase() { # n codec w h secs
  echo "$(date -u +%H:%M:%S) phase=$1 codec=$2 size=$3x$4 secs=$5" | tee -a "$OUT/events.log"
  "$HOST" --no-control-server --bind-ip "$BIND" --client-ip "$VIEWER_IP" --client-port 38402 \
    --codec "$2" --width "$3" --height "$4" --fps 60 --bitrate-mbps 18 --keyframe-interval 60 \
    --duration "$5" --display-id "$DISPLAY_ID" --output /dev/null > "$OUT/host-phase$1.log" 2>&1
  echo "$(date -u +%H:%M:%S) phase=$1 end rc=$?" | tee -a "$OUT/events.log"
}
phase 1 h264 1920 1080 12
GAP=${JERISLINK_REPRO_GAP:-12}
echo "$(date -u +%H:%M:%S) gap ${GAP}s" | tee -a "$OUT/events.log"; sleep "$GAP"
phase 2 h264 1920 1080 10
phase 3 hevc 1920 1080 10
phase 4 h264 1920 1080 10
phase 5 h264 1280 720 10
phase 6 h264 1920 1080 10
echo "$(date -u +%H:%M:%S) done" | tee -a "$OUT/events.log"
