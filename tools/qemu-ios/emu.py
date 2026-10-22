#!/usr/bin/env python3
"""Run a SWEETXNU payload in QEMU virt and serve a live view of its screen.

  emu.py PAYLOAD OUTDIR [--cpu cortex-a76] [--smp 1] [--port 8080]

http://localhost:PORT/       live framebuffer (refreshes ~1/s)
http://localhost:PORT/log    kernel message buffer (msgbuf)
"""
import argparse, importlib.util, io, json, os, socket, struct, subprocess, sys, threading, time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('qs', os.path.expanduser('~/ios-topaz/tools/qemu-sweet.py'))
qs = importlib.util.module_from_spec(spec); spec.loader.exec_module(qs)


class QMP:
    def __init__(self, path):
        self.lock = threading.Lock()
        for _ in range(100):
            try:
                self.s = socket.socket(socket.AF_UNIX); self.s.connect(path); break
            except OSError:
                time.sleep(0.1)
        self.f = self.s.makefile('rw'); self.f.readline()
        self.call('qmp_capabilities')

    def call(self, execute, **args):
        with self.lock:
            self.f.write(json.dumps({'execute': execute, 'arguments': args}) + '\n'); self.f.flush()
            while True:
                r = json.loads(self.f.readline())
                if 'return' in r or 'error' in r:
                    return r

    def hmp(self, line):
        return self.call('human-monitor-command', **{'command-line': line}).get('return', '')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('payload'); ap.add_argument('outdir')
    ap.add_argument('--cpu', default='cortex-a76'); ap.add_argument('--smp', default='1')
    ap.add_argument('--qemu', default='/opt/qemu9/bin/qemu-system-aarch64')
    ap.add_argument('--port', type=int, default=8080)
    ap.add_argument('--kernel', default=os.path.expanduser('~/ios-topaz/xnu/out/kernel.development.sweet'))
    ap.add_argument('--snap-every', type=float, default=30)
    ap.add_argument('--net', action='store_true', help='virtio-net (user-mode NAT) for sweetvnet=1')
    ap.add_argument('--incoming', help='restore a booted state saved with /save (mapped-ram migration file)')
    ap.add_argument('--vinput', action='store_true', help='virtio tablet + keyboard for sweetvinput=1 (no gdb touch relay)')
    a = ap.parse_args()
    out = os.path.abspath(a.outdir); os.makedirs(out, exist_ok=True)
    meta = json.load(open(a.payload))
    open(f'{out}/stub.bin', 'wb').write(qs.stub(meta['ba_pa'], meta['entry_pa']))
    syms = subprocess.check_output(['llvm-nm', '--defined-only', a.kernel], text=True)
    msgbufp = next(int(l.split()[0], 16) for l in syms.splitlines() if l.endswith(' _msgbufp'))
    ram_gib = meta['ram_gib']
    mon = f'{out}/mon.sock'
    if os.path.exists(mon): os.unlink(mon)
    ramobj = f"memory-backend-file,id=ram0,size={ram_gib}G,mem-path={meta['ram']},share=off"
    if a.incoming:  # pages missing from a mapped-ram file must read as zero, so no file-backed RAM here
        ramobj = f"memory-backend-ram,id=ram0,size={ram_gib}G"
    cmd = [a.qemu, '-object', ramobj,
           '-M', 'virt,gic-version=3,memory-backend=ram0', '-cpu', a.cpu, '-smp', a.smp, '-m', f'{ram_gib}G',
           '-nographic', '-serial', f'file:{out}/serial.txt', '-qmp', f'unix:{mon},server,nowait',
           '-d', 'guest_errors,unimp', '-D', f'{out}/qemu.log', '-no-reboot', '-gdb', f'tcp::{os.environ.get("GDBPORT","1234")}',
           '-device', f'loader,file={out}/stub.bin,addr={qs.STUB_PA:#x},force-raw=on',
           '-device', f'loader,addr={qs.STUB_PA:#x},cpu-num=0']
    if a.net:
        cmd += ['-global', 'virtio-mmio.force-legacy=false',
                '-netdev', f'user,id=n0,net=10.0.2.0/24,dns=10.0.2.3,hostfwd=tcp:127.0.0.1:7777-10.0.2.15:7777',
                '-device', 'virtio-net-device,netdev=n0,mac=02:54:4f:50:41:5c',
                '-object', f'filter-dump,id=d0,netdev=n0,file={out}/net.pcap']
    if a.vinput:
        cmd += ['-global', 'virtio-mmio.force-legacy=false',
                '-device', 'virtio-tablet-device', '-device', 'virtio-keyboard-device']
    if a.incoming:
        cmd += ['-incoming', 'defer']
    print(' '.join(cmd), file=sys.stderr)
    p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL)
    q = QMP(mon)
    t0 = time.time()
    def migwait():
        while True:
            st = q.call('query-migrate')['return'].get('status')
            if st in ('completed', 'failed', 'cancelled', None): return st
            time.sleep(0.5)
    if a.incoming:
        q.call('migrate-set-capabilities', capabilities=[{'capability': 'mapped-ram', 'state': True}])
        r = q.call('migrate-incoming', uri=f'file:{os.path.abspath(a.incoming)}')
        print('restore', r, migwait(), f'{time.time() - t0:.1f} s', file=sys.stderr)
        q.call('cont')
    lock = threading.Lock()

    def frame(scale=2):
        with lock:
            r = q.call('pmemsave', val=qs.FB_BASE, size=qs.FB_STRIDE * qs.FB_H, filename=f'{out}/fb.raw')
            raw = open(f'{out}/fb.raw', 'rb').read()
        im = Image.frombuffer('RGBX', (qs.FB_W, qs.FB_H), raw, 'raw', 'BGRX', 0, 1).convert('RGB')
        if scale > 1: im = im.resize((qs.FB_W // scale, qs.FB_H // scale), Image.BILINEAR)
        return im

    mb = {}
    def msgbuf():
        def hx(cmd):
            for c in range(int(a.smp)):
                r = q.hmp(cmd)
                if not any(w in r for w in ('Cannot access', 'memory', 'Unmapped')):
                    return r
                q.hmp(f'cpu {c}')
            raise RuntimeError(f'{cmd}: {r.strip()}')
        def pa(va):
            r = hx(f'gva2gpa {va:#x}')
            return int(r.split()[-1], 16)
        with lock:
            if 'pst' not in mb:
                # iOS unmaps the kernel while a CPU is in user mode, so resolve the
                # msgbuf to physical addresses once and read it physically afterwards.
                st = int(hx(f'x /1gx {msgbufp:#x}').split()[-1], 16)
                bufc = int(hx(f'x /3gx {st:#x}').split()[-1], 16)
                mb.update(pst=pa(st), pbuf=pa(bufc), pend=pa(bufc + 0x1fff0))
            w = [int(x, 16) for x in q.hmp(f'xp /4wx {mb["pst"]:#x}').split()[1:5]]
            size, bufx = w[1], w[2]
            if mb['pend'] - mb['pbuf'] != 0x1fff0 or not 0 < size <= 0x100000 or bufx > size:
                mb.clear(); raise RuntimeError(f'msgbuf layout changed w={w}')
            r = q.call('pmemsave', val=mb['pbuf'], size=size, filename=f'{out}/msgbuf.raw')
            if 'error' in r:
                mb.clear(); raise RuntimeError(f'pmemsave: {r}')
            raw = open(f'{out}/msgbuf.raw', 'rb').read()
        raw = raw[bufx:] + raw[:bufx]
        return raw.replace(b'\0', b'').decode('utf-8', 'replace')

    def snapper():
        n = 0
        while p.poll() is None:
            time.sleep(a.snap_every)
            try:
                frame(1).save(f'{out}/fb-latest.png')
                frame(2).save(f'{out}/snap-{int(time.time()-t0):05d}.jpg', quality=80)
                open(f'{out}/msgbuf.txt', 'w').write(msgbuf())
            except Exception as e:
                print('snap error', e, file=sys.stderr)
    threading.Thread(target=snapper, daemon=True).start()

    page = b'''<!doctype html><html><head><title>ios-topaz in QEMU</title><style>
body{background:#111;color:#ccc;font:13px monospace;margin:0;display:flex;gap:12px;padding:12px}
img{height:92vh;border:1px solid #444}pre{flex:1;height:92vh;overflow:auto;white-space:pre-wrap;margin:0}
</style></head><body><div><img id=f src="/fb.jpg" draggable=false style="cursor:pointer;touch-action:none"><div style="margin-top:6px"><button onclick="fetch('/unlock')">Wake + unlock</button> <button onclick="fetch('/home')">Home</button> <span id=t></span><br>Click/drag = touch. Type or paste anywhere on this page = keyboard.</div></div><div style="flex:1"><div id=s></div><pre id=l></pre></div><script>
const f=document.getElementById('f'),l=document.getElementById('l'),s=document.getElementById('s');
function tick(){const i=new Image();i.onload=()=>{f.src=i.src;setTimeout(tick,150)};i.onerror=()=>setTimeout(tick,2000);i.src='/fb.jpg?'+Date.now()}
async function log(){try{const r=await fetch('/log');const t=await r.text();const b=l.scrollTop+l.clientHeight>=l.scrollHeight-20;l.textContent=t;if(b)l.scrollTop=l.scrollHeight;
s.textContent=(await (await fetch('/status')).text())}catch(e){}setTimeout(log,4000)}
let d=null,lt=0,chain=Promise.resolve();const P=e=>{const r=f.getBoundingClientRect();return [Math.round((e.clientX-r.left)/r.width*1080),Math.round((e.clientY-r.top)/r.height*2400)]};
const tx=u=>{chain=chain.then(()=>fetch(u)).catch(()=>{})};const T=document.getElementById('t');
f.onpointerdown=e=>{e.preventDefault();f.setPointerCapture(e.pointerId);d=P(e);tx(`/touch?d=1&x=${d[0]}&y=${d[1]}`);T.textContent='touch'};
f.onpointermove=e=>{if(!d||Date.now()-lt<30)return;lt=Date.now();const [x,y]=P(e);tx(`/touch?d=1&x=${x}&y=${y}`)};
f.onpointerup=e=>{if(!d)return;const [x,y]=P(e);tx(`/touch?d=1&x=${x}&y=${y}`);tx(`/touch?d=0&x=${x}&y=${y}`);d=null;T.textContent=''};
const KM={Enter:'ret',Backspace:'backspace',Tab:'tab',Escape:'esc',ArrowLeft:'left',ArrowRight:'right',ArrowUp:'up',ArrowDown:'down',Delete:'delete'};
document.onkeydown=e=>{if(e.target.tagName=='INPUT')return;if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()=='v')return;let u=null;const m=[e.metaKey?'meta_l':'',e.ctrlKey?'ctrl':'',e.altKey?'alt':''].filter(x=>x).join(',');
if(KM[e.key])u=`/key?q=${KM[e.key]}&mods=${m}`;else if(e.key.length==1)u=m?`/key?q=${encodeURIComponent(e.key.toLowerCase())}&mods=${m}`:`/type?text=${encodeURIComponent(e.key)}`;
if(u){e.preventDefault();tx(u);T.textContent='typing'}};
document.onpaste=e=>{const t=e.clipboardData.getData('text');if(t){e.preventDefault();tx('/type?text='+encodeURIComponent(t))}};
tick();log();</script></body></html>'''

    import queue
    inq = queue.Queue()
    BTN = ['power', 'volumeup', 'volumedown', 'ac_home']
    def kev(qc, down): return {'type': 'key', 'data': {'down': down, 'key': {'type': 'qcode', 'data': qc}}}
    def run_step(step):
        k, v = step.split(':'); v = [int(x) for x in v.split(',')]
        if k == 'sleep': time.sleep(v[0] / 1000); return
        if k == 'touch':
            ev = [{'type': 'abs', 'data': {'axis': 'x', 'value': v[2] * 32767 // 1079}},
                  {'type': 'abs', 'data': {'axis': 'y', 'value': v[3] * 32767 // 2399}},
                  {'type': 'btn', 'data': {'down': bool(v[1]), 'button': 'left'}}]
        else:
            ev = [kev(BTN[v[0]], bool(v[1]))]
        q.call('input-send-event', events=ev)
    def input_worker():
        while True:
            item = inq.get()
            try:
                if isinstance(item, list) and item and isinstance(item[0], str):
                    for st in item: run_step(st)
                else:
                    q.call('input-send-event', events=item)
            except Exception as e:
                print('input error', e, file=sys.stderr)
    if a.vinput: threading.Thread(target=input_worker, daemon=True).start()
    CH = {' ': 'spc', '\n': 'ret', '\t': 'tab', '-': 'minus', '=': 'equal', '[': 'bracket_left', ']': 'bracket_right',
          '\\': 'backslash', ';': 'semicolon', "'": 'apostrophe', '`': 'grave_accent', ',': 'comma', '.': 'dot', '/': 'slash'}
    SH = dict(zip('!@#$%^&*()_+{}|:"~<>?', '1234567890-=[]\\;\'`,./'))
    def type_events(text):
        evs = []
        for c in text:
            shift = c.isupper() or c in SH
            b = SH.get(c, c.lower()); qc = CH.get(b, b)
            if not (qc.isalnum() or qc in CH.values()): continue
            # iOS drops keys sent back to back: hold each key ~25 ms and leave a gap before the next one
            if shift: evs += [[kev('shift', True)], ['sleep:15']]
            evs += [[kev(qc, True)], ['sleep:25'], [kev(qc, False)], ['sleep:25']]
            if shift: evs += [[kev('shift', False)], ['sleep:15']]
        return evs

    class H(BaseHTTPRequestHandler):
        def log_message(self, *x): pass
        def send(self, ctype, body):
            self.send_response(200); self.send_header('Content-Type', ctype)
            self.send_header('Cache-Control', 'no-store'); self.send_header('Content-Length', str(len(body)))
            self.end_headers(); self.wfile.write(body)
        def do_GET(self):
            path = self.path.split('?')[0]
            try:
                if path == '/':
                    self.send('text/html', page)
                elif path == '/fb.jpg':
                    b = io.BytesIO(); frame(2).save(b, 'JPEG', quality=80); self.send('image/jpeg', b.getvalue())
                elif path == '/fb.png':
                    b = io.BytesIO(); frame(1).save(b, 'PNG'); self.send('image/png', b.getvalue())
                elif path == '/log':
                    self.send('text/plain; charset=utf-8', msgbuf().encode())
                elif path == '/hmp':
                    import urllib.parse
                    c = urllib.parse.unquote(self.path.split('?', 1)[1])
                    with lock: r = q.hmp(c)
                    self.send('text/plain', r.encode())
                elif path in ('/tap', '/swipe', '/unlock', '/home'):
                    import urllib.parse
                    qs = {k: int(float(v[0])) for k, v in urllib.parse.parse_qs(self.path.partition('?')[2]).items()}
                    def swipe(x1, y1, x2, y2, ms):
                        n = max(4, min(20, ms // 16)); st = [f'touch:0,1,{x1},{y1}', 'sleep:30']
                        for i in range(1, n + 1):
                            st += [f'touch:0,1,{x1 + (x2 - x1) * i // n},{y1 + (y2 - y1) * i // n}', f'sleep:{max(8, ms // n)}']
                        return st + [f'touch:0,0,{x2},{y2}']
                    home = ['key:3,1', 'sleep:100', 'key:3,0']
                    if path == '/tap':
                        st = [f'touch:0,1,{qs["x"]},{qs["y"]}', 'sleep:80', f'touch:0,0,{qs["x"]},{qs["y"]}']
                    elif path == '/swipe':
                        st = swipe(qs['x1'], qs['y1'], qs['x2'], qs['y2'], qs.get('ms', 300))
                    elif path == '/unlock':
                        st = home + ['sleep:1500'] + swipe(540, 2392, 540, 950, 330)
                    else:
                        st = home
                    if a.vinput:
                        inq.put(st); self.send('text/plain', b'sent\n'); return
                    qd = f'{out}/touchq'; os.makedirs(qd, exist_ok=True)
                    fn = f'{qd}/{time.time():.6f}'
                    open(fn + '.tmp', 'w').write(';'.join(st)); os.rename(fn + '.tmp', fn + '.cmd')
                    self.send('text/plain', b'queued\n')
                elif path in ('/touch', '/key', '/type') and a.vinput:
                    import urllib.parse
                    qs = {k: v[0] for k, v in urllib.parse.parse_qs(self.path.partition('?')[2], keep_blank_values=True).items()}
                    if path == '/touch':
                        inq.put([f'touch:0,{int(qs["d"])},{int(float(qs["x"]))},{int(float(qs["y"]))}'])
                    elif path == '/key':
                        mods = [m for m in qs.get('mods', '').split(',') if m]
                        evs = [[kev(m, True)] for m in mods] + [['sleep:15'], [kev(qs['q'], True)], ['sleep:40'], [kev(qs['q'], False)], ['sleep:15']] + [[kev(m, False)] for m in mods]
                        for e in evs: inq.put(e)
                    else:
                        for e in type_events(qs.get('text', '')): inq.put(e)
                    self.send('text/plain', b'sent\n')
                elif path == '/save':
                    import urllib.parse
                    fn = os.path.abspath(urllib.parse.parse_qs(self.path.partition('?')[2])['file'][0])
                    t1 = time.time()
                    with lock:
                        q.call('migrate-set-capabilities', capabilities=[{'capability': 'mapped-ram', 'state': True}])
                        if os.path.exists(fn): os.unlink(fn)
                        r = q.call('migrate', uri=f'file:{fn}'); st = migwait(); q.call('cont')
                    self.send('text/plain', f'{r} {st} {time.time() - t1:.1f} s\n'.encode())
                elif path == '/status':
                    self.send('text/plain', f'QEMU {"running" if p.poll() is None else "exited"}, {int(time.time()-t0)} s since power-on, cpu={a.cpu} x{a.smp}\n'.encode())
                else:
                    self.send_error(404)
            except Exception as e:
                self.send('text/plain', f'error: {e}'.encode())
    srv = ThreadingHTTPServer(('0.0.0.0', a.port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f'live view on http://localhost:{a.port}/', file=sys.stderr)
    p.wait()
    print('qemu exited', p.returncode, file=sys.stderr)
    time.sleep(5)


if __name__ == '__main__':
    main()
