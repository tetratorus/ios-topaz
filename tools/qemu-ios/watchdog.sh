#!/bin/bash
# watchdog.sh RUNDIR: reboot the guest via boot.sh if QEMU dies, the kernel panics (e.g. after the
# Devin VM sleeps), the screen is still the Apple logo (logo.jpg) after 20 min, or the guest is
# frozen: a lit screen (the status-bar/lock-screen clock changes every minute) and the kernel log
# both unchanged for 5 min.
cd ~/emu; RUN=${1:-r21}
logo=$(md5sum < logo.jpg | cut -c1-32); same=0; frozen=0; lastfb=; lastlog=
reboot() { echo "$(date +%T) $1, restarting (start.sh) from $RUN" >> watchdog.log; same=0; frozen=0; setsid ./start.sh >> watchdog.log 2>&1 < /dev/null; exit 0; }
lit() { python3 -c "import sys,io;from PIL import Image;sys.exit(0 if Image.open(io.BytesIO(sys.stdin.buffer.read())).convert('L').getextrema()[1]>40 else 1)"; }
while sleep 30; do
  if ! pgrep -f "^/opt/qemu9/bin/qemu-system" >/dev/null; then reboot "qemu down"; continue; fi
  if strings -n 8 "$RUN/msgbuf.raw" 2>/dev/null | grep -aq -E "panic\(cpu|Ticket spinlock timeout"; then reboot "kernel panic"; continue; fi
  curl -s -m 20 localhost:8099/fb.jpg > "$RUN/.wd.jpg"
  fb=$(md5sum < "$RUN/.wd.jpg" | cut -c1-32); lg=$(md5sum < "$RUN/msgbuf.raw" 2>/dev/null | cut -c1-32)
  if [ "$fb" = "$logo" ]; then same=$((same+1)); else same=0; fi
  [ $same -ge 40 ] && { reboot "stuck on Apple logo 20 min"; continue; }
  if [ "$fb" = "$lastfb" ] && [ "$lg" = "$lastlog" ] && lit < "$RUN/.wd.jpg"; then frozen=$((frozen+1)); else frozen=0; fi
  lastfb=$fb; lastlog=$lg
  [ $frozen -ge 10 ] && reboot "guest frozen 5 min (screen and kernel log unchanged)"
done
