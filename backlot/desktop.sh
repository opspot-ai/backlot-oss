#!/bin/bash
set -euo pipefail

export DISPLAY=:99
width="${BACKLOT_WIDTH:-1280}"
height="${BACKLOT_HEIGHT:-720}"
depth="${BACKLOT_DEPTH:-24}"
password="${BACKLOT_VNC_PASSWORD:?missing BACKLOT_VNC_PASSWORD}"

mkdir -p /run/dbus /root/Desktop
dbus-daemon --system --fork || true
eval "$(dbus-launch --sh-syntax)"

launcher() {
  local name="$1"
  local command="$2"
  local icon="$3"
  local path="/root/Desktop/${name}.desktop"
  printf '[Desktop Entry]\nType=Application\nName=%s\nExec=%s\nIcon=%s\nTerminal=false\n' \
    "$name" "$command" "$icon" >"$path"
  chmod +x "$path"
  gio set --type=string "$path" metadata::trusted true || true
  gio set --type=string "$path" metadata::xfce-exe-checksum \
    "$(sha256sum "$path" | cut -d' ' -f1)" || true
  touch "$path"
}

launcher "Terminal" "xfce4-terminal --working-directory=/root/Desktop" "utilities-terminal"
launcher "Files" "thunar /" "system-file-manager"
launcher "Chromium" "chromium --no-sandbox --disable-dev-shm-usage --disable-gpu --no-first-run --no-default-browser-check --disable-session-crashed-bubble --password-store=basic" "chromium"
launcher "Text Editor" "mousepad" "accessories-text-editor"
update-desktop-database /root/Desktop || true

rm -f /tmp/.X99-lock /tmp/.X11-unix/X99
Xvfb :99 -screen 0 "${width}x${height}x${depth}" -ac +extension RANDR &
sleep 1
xfwm4 >/tmp/xfwm4.log 2>&1 &
sleep 1
xfdesktop --disable-wm-check >/tmp/xfdesktop.log 2>&1 &
x11vnc -storepasswd "$password" /tmp/backlot-vnc.pass
x11vnc -display :99 -forever -shared -localhost -rfbport 5900 \
  -rfbauth /tmp/backlot-vnc.pass >/tmp/x11vnc.log 2>&1 &
websockify --web=/usr/share/novnc/ 6080 localhost:5900 >/tmp/websockify.log 2>&1 &

# Tenant boot hook. Processes do not survive a stop/start, only disk does, so a
# tenant runtime is dead after every idle reap, rollover, and action auto-start.
# This runs on all of them. Deliberately dumb: fire and forget, never blocks the
# desktop, never fails the boot. Idempotency and health checks belong to the hook.
backlot_hook=/opt/backlot/on-boot.sh
if [ -f "$backlot_hook" ]; then
  chmod +x "$backlot_hook" 2>/dev/null || true
  setsid nohup "$backlot_hook" >>/var/log/backlot-on-boot.log 2>&1 &
fi

uvicorn backlot.agent:app --host 0.0.0.0 --port 8080
