#!/usr/bin/env python3
"""prepkern.py KERNEL OUT : apply 64-bit _mdevstrategy fix + print gtouchd addrs."""
import struct,subprocess,sys
k,out=sys.argv[1],sys.argv[2]
d=bytearray(open(k,'rb').read())
syms={}
for l in subprocess.check_output(['llvm-nm',k],text=True).splitlines():
    p=l.split()
    if len(p)==3: syms[p[2]]=int(p[0],16)
def va2off(va):
    ncmds=struct.unpack_from('<I',d,16)[0];o=32
    for _ in range(ncmds):
        cmd,sz=struct.unpack_from('<II',d,o)
        if cmd==0x19:
            vm,vs,fo,fs=struct.unpack_from('<QQQQ',d,o+24)
            if vm<=va<vm+fs: return fo+va-vm
        o+=sz
    raise SystemExit('va not mapped %x'%va)
s=va2off(syms['_mdevstrategy']);n=0
for i in range(s,s+0x400,4):
    if d[i:i+4]==bytes.fromhex('084d1453'): d[i:i+4]=bytes.fromhex('08cd74d3');n+=1
print('mdev patched words:',n,'(expect 2)')
open(out,'wb').write(d)
for nm in ['__ZN15SweetHIDButtons9testFiredEP8OSObjectP18IOTimerEventSource','__ZN18IOTimerEventSource12setTimeoutMSEj','_sweet_hid_touch','_sweet_hid_key','_IOSleep','_sweet_vnet_start']:
    print(nm,hex(syms.get(nm,0)))
