# qemu-ios: iOS 16.7.16 (iPhone X userspace) on the ios-topaz kernel in QEMU, simulator-style

Host: Ubuntu x86_64, QEMU 9.2 at /opt/qemu9 (cortex-a76 build; env `QEMU_A76_NOPAN=1 VIRT_MPIDR_OR=0x100 QEMU_PSCI_SMC=1`).
These scripts expect to live in `~/emu` (copy this directory there) next to `kernel.vinput`, `qmid4m.adt`, and `~/ipsw/qroot-app.img`.

- `start.sh` restores the saved booted phone `snaps/home.mig` (~20 s); `start.sh --fresh` boots from scratch (~6 min) and saves a new snapshot once the home screen is up.
- Viewer: http://localhost:8099 . Click/drag = touch, typing/paste on the page = hardware keyboard (QMP `input-send-event` -> QEMU virtio-tablet/keyboard -> kernel 0141 `sweet_vinput.c`, boot-arg `sweetvinput=1`). No gdb in the input path.
- `iosctl` (simctl-like): `tap`, `swipe`, `type`, `key`, `home`, `screenshot`, `save`, `install PATH [--launch]` (`.app`/`.ipa`/`.zip`, ad-hoc signed with ldid, no root image rebuild), `launch`, `terminate`, `uninstall`, `openurl`, `apps`, `ping`, `log`.
- `topazd/`: root guest agent (HTTP on guest :7777, QEMU hostfwd 127.0.0.1:7777). Built on macOS with Xcode 15.4 (`build.sh`). Installed into the root image at `/usr/local/bin/topazd`, job added to `/System/Library/xpc/launchd.plist` under the `/System/Library/LaunchDaemons/org.sweet.topazd.plist` key (a `/Library/LaunchDaemons/...` key is never started) and a jetsam override `org.sweet.topazd` {ActiveSoftMemoryLimit 512, InactiveHardMemoryLimit 512} in `com.apple.jetsamproperties.D22.plist` (default daemon limit is 6 MB; `/apps` got jetsam-killed). No StandardOutPath (it stops launchd jobs from starting on this image).
- `prepkern.py IN OUT`: runtime fix applied to every kernel (64-bit `_mdevstrategy`, needed for the 9 GB RAM-disk root).
- `boot.sh RUN` (fresh boot; `VINPUT=1` selects kernel.vinput), `watchdog.sh RUN` (restarts via start.sh when QEMU dies or the guest panics/freezes), `bigboot.py` (builds the guest RAM file), `emu.py` (QEMU + viewer + QMP input + `/save` mapped-ram migration).
