#!/usr/bin/env python3
"""Build a sparse QEMU guest-RAM file (RAM starts at 0x40000000) holding the
SWEETXNU kernel + ADT + boot_args + a large root image as md0, so QEMU can map it
with memory-backend-file,share=off instead of copying gigabytes into a ROM blob.
  bigboot.py KERNEL ADT ROOTIMG OUT.ram --cmdline "..."   -> OUT.ram + OUT.ram.json"""
import argparse, importlib.util, json, os, struct

def load(name, path):
    s = importlib.util.spec_from_file_location(name, os.path.expanduser(path))
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
mp = load('mp', '~/ios-topaz/tools/mkpayload.py')
qs = load('qs', '~/ios-topaz/tools/qemu-sweet.py')
RAM0 = 0x40000000

ap = argparse.ArgumentParser()
ap.add_argument('kernel'); ap.add_argument('adt'); ap.add_argument('root'); ap.add_argument('out')
ap.add_argument('--cmdline', required=True)
a = ap.parse_args()
blob, _ = mp.build(a.kernel, a.adt, a.cmdline)
_, _, nsegs = struct.unpack_from('<8sII', blob, 0)
virt_base, entry_va, adt_off, adt_size, kernel_end, phys_base, mem_size = struct.unpack_from('<7Q', blob, 0x10)
delta = phys_base - virt_base
rd_size = (os.path.getsize(a.root) + qs.PAGE - 1) & ~(qs.PAGE - 1)
rd_pa = kernel_end + delta
kernel_end += rd_size
adt_blob = mp.add_ramdisk_to_adt(open(a.adt, 'rb').read(), rd_pa, rd_size)
adt_pa = kernel_end + delta
ba_pa = (adt_pa + len(adt_blob) + qs.PAGE - 1) & ~(qs.PAGE - 1)
top = ba_pa + qs.PAGE
ram_gib = -(-(phys_base + mem_size - RAM0) // (1 << 30))
cmdline = blob[0x48:0x48 + qs.BOOT_LINE_LENGTH]
ba = struct.pack('<HH4x4Q6QI4xQI', 2, 2, virt_base, phys_base, mem_size, top,
                 qs.FB_BASE, 1, qs.FB_STRIDE, qs.FB_W, qs.FB_H, 32, 0, adt_pa - delta, len(adt_blob))
ba += cmdline + b'\0' * 4 + struct.pack('<QQ', 0, mem_size)
with open(a.out, 'wb') as f:
    f.truncate(ram_gib << 30)
    for i in range(nsegs):
        vmaddr, vmsize, foff, fsize = struct.unpack_from('<4Q', blob, 0x2a8 + 32 * i)
        f.seek(vmaddr + delta - RAM0); f.write(blob[foff:foff + fsize])
    f.seek(adt_pa - RAM0); f.write(adt_blob)
    f.seek(ba_pa - RAM0); f.write(ba)
    with open(a.root, 'rb') as r:
        off, n = rd_pa - RAM0, os.path.getsize(a.root)
        while n:
            c = os.copy_file_range(r.fileno(), f.fileno(), min(n, 1 << 30), offset_dst=off)
            off += c; n -= c
meta = dict(ram=os.path.abspath(a.out), ram_gib=ram_gib, ba_pa=ba_pa, entry_pa=entry_va + delta,
            rd=(hex(rd_pa), hex(rd_size)), phys_base=hex(phys_base), mem_size=hex(mem_size))
json.dump(meta, open(a.out + '.json', 'w'), indent=1); print(meta)
