#!/bin/bash
# start.sh: iOS phone on http://localhost:8099 in ~30 s, restored from the saved booted state snaps/home.mig.
#   ./start.sh          restore the saved home screen (falls back to a fresh boot + save if there is none)
#   ./start.sh --fresh  fresh boot (~6 min), then save a new snaps/home.mig once the home screen is up
# Everything changed in the phone (installed apps, settings) lives in RAM: it is lost on the next start
# unless you save it with:  ./iosctl save
set -e
cd ~/emu
SNAP=snaps/home.mig; RUN=r-$(date +%m%d-%H%M%S); PORT=8099
for p in $(pgrep -f "^/bin/bash ./watchdog.sh"); do kill $p; done
pkill -f "emu.py guest" || true; pkill -f "^/opt/qemu9/bin/qemu-system" || true
for i in $(seq 1 30); do ss -ltn | grep -q ":$PORT " || break; sleep 1; done
if [ "$1" = --fresh ] || [ ! -f $SNAP ]; then
  VINPUT=1 ./boot.sh $RUN
  # Apple-logo frames are small JPEGs (<20 KB), the home screen is >40 KB: wait for logo, then for home (boot.sh unlocks)
  logo=0; for i in $(seq 1 120); do sleep 10; sz=$(curl -s -m 10 localhost:$PORT/fb.jpg | wc -c)
    if [ "$sz" -gt 1000 ] && [ "$sz" -lt 20000 ]; then logo=1; elif [ $logo = 1 ] && [ "$sz" -gt 40000 ]; then break; fi; done
  sleep 60; ./iosctl home; sleep 5; ./iosctl save
else
  mkdir -p $RUN; t0=$(date +%s)
  QEMU_A76_NOPAN=1 VIRT_MPIDR_OR=0x100 QEMU_PSCI_SMC=1 GDBPORT=1240 nohup python3 emu.py guest12.ram.json $RUN \
    --port $PORT --smp 4 --snap-every 60 --net --vinput --kernel ~/emu/kernel.vinput --incoming $SNAP > $RUN/emu.log 2>&1 &
  for i in $(seq 1 120); do grep -q "^restore" $RUN/emu.log 2>/dev/null && break; sleep 1; done
  grep "^restore" $RUN/emu.log; echo "restored in $(( $(date +%s) - t0 )) s"
fi
ln -sfn $RUN current
VINPUT=1 ./rewd.sh $RUN
echo "phone: http://localhost:$PORT   (run dir ~/emu/$RUN, control with ~/emu/iosctl)"
