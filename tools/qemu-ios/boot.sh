#!/bin/bash
# boot.sh [RUNDIR]: fresh iOS boot in QEMU straight to the home screen, with network and touch.
# Builds guest RAM (kernel.vnet2 + qmid4m.adt + qroot-app.img), starts QEMU on :8099 (gdb :1240),
# attaches the touch daemon once the lock screen is up (attaching during early boot froze r22), then unlocks.
set -e
cd ~/emu
RUN=${1:-r21}; PORT=8099; GDBPORT=1240
# VINPUT=1: kernel with patch 0141 (virtio tablet/keyboard, sweetvinput=1); input goes through QMP, no gdb relay.
VINPUT=${VINPUT:-0}; KERNEL=kernel.vnet2; RAMF=guest11; EMUFLAGS=
CMDLINE="debug=0xc serial=3 cpus=4 keepsyms=1 -enable_kprintf_spam -noprogress rd=md0 unentitled_ios_sim_launch=1 ignition_level=1 wdt_test=no_user_checkin wdt=-1 launchd_unsecure_cache=1 rootrw=1 sweetfb_noconsole=1 sweetfb_hz=30 sweettouch=0 sweetkeys=0 sweetbattery=0 sweetcpufreq=0 sweetusb=0 sweetfb_direct=0 sweetbl=0 sweethidtest=60 sweetvnet=1 slto_us=20000000 tlto_us=10000000"
[ "$VINPUT" = 1 ] && { KERNEL=kernel.vinput; RAMF=guest12; EMUFLAGS=--vinput; CMDLINE=${CMDLINE/sweethidtest=60/sweetvinput=1}; }
pkill -f "gdb-multiarch -q -batch -x gtouchd.py" || true
pkill -f "emu.py guest" || true
pkill -f "^/opt/qemu9/bin/qemu-system" || true
for i in $(seq 1 30); do ss -ltn | grep -q ":$PORT " || break; sleep 1; done
rm -rf "$RUN"; mkdir -p "$RUN/touchq"
[ -f $RAMF.ram.json ] && [ $RAMF.ram.json -nt ~/ipsw/qroot-app.img ] && [ $RAMF.ram.json -nt $KERNEL ] && [ "$(cat $RAMF.cmdline 2>/dev/null)" = "$CMDLINE" ] || {
  python3 bigboot.py $KERNEL qmid4m.adt ~/ipsw/qroot-app.img $RAMF.ram --cmdline "$CMDLINE" > "$RUN/bigboot.log" 2>&1
  echo "$CMDLINE" > $RAMF.cmdline; }
QEMU_A76_NOPAN=1 VIRT_MPIDR_OR=0x100 QEMU_PSCI_SMC=1 GDBPORT=$GDBPORT nohup python3 emu.py $RAMF.ram.json "$RUN" \
  --port $PORT --smp 4 --snap-every 60 --net $EMUFLAGS --kernel ~/emu/$KERNEL > "$RUN/emu.log" 2>&1 &
for i in $(seq 1 60); do ss -ltn | grep -q ":$GDBPORT " && break; sleep 1; done
(   # Apple-logo frames are tiny JPEGs (~12 KB); the lock screen is much bigger. Unlock once it appears.
  logo=0; for i in $(seq 1 240); do
    sz=$(curl -s -m 10 localhost:$PORT/fb.jpg | wc -c)
    if [ "$sz" -gt 1000 ] && [ "$sz" -lt 20000 ]; then logo=1; elif [ $logo = 1 ] && [ "$sz" -ge 20000 ]; then break; fi
    sleep 10; done
  [ "$VINPUT" = 1 ] || KADDRS=vnet2 GDBPORT=$GDBPORT TOUCHQ=$PWD/$RUN/touchq nohup gdb-multiarch -q -batch -x gtouchd.py > "$RUN/gtouchd.log" 2>&1 < /dev/null &
  [ "$VINPUT" = 1 ] || for i in $(seq 1 60); do grep -q "timer owned" "$RUN/gtouchd.log" 2>/dev/null && break; sleep 5; done
  # The lock screen JPEG is ~20 KB, the home screen ~60 KB+: keep unlocking (Home + edge swipe) until it is up.
  for n in $(seq 1 10); do sleep 60; [ "$(curl -s -m 10 localhost:$PORT/fb.jpg | wc -c)" -gt 40000 ] && break; curl -s -m 5 localhost:$PORT/unlock >/dev/null; done ) > /dev/null 2>&1 &
echo "booting $RUN: viewer http://localhost:$PORT  (touch log $RUN/gtouchd.log, packets $RUN/net.pcap)"
