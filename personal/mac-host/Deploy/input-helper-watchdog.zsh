#!/bin/zsh
APP="$HOME/Applications/JerisLink Input Helper.app"
EXE="$APP/Contents/MacOS/JerisLinkInputHelper"
LOG="/tmp/jerislink-input-helper-watchdog.log"
RUNLOG="/tmp/jerislink-input-helper.log"

while true; do
    if ! /usr/bin/pgrep -f "^$EXE$" >/dev/null 2>&1; then
        print -r -- "$(/bin/date '+%Y-%m-%d %H:%M:%S') JerisLink Input Helper missing; launching executable" >> "$LOG"
        "$EXE" >> "$RUNLOG" 2>&1 &
    fi
    /bin/sleep 5
done
