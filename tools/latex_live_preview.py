# -*- coding: utf-8 -*-
"""
latex_live_preview.py - Xem truoc LaTeX tu dong lam moi.

Theo doi moi tep .tex trong thu muc chi dinh. Moi khi mot tep thay doi,
bien dich lai bang Tectonic, roi trang xem truoc o trinh duyet tu tai lai PDF.

Chay:  python3 latex_live_preview.py <thu_muc_chua_tex> [cong]
Mo:    http://localhost:8765
"""
import json, os, subprocess, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

ROOT = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8765
TECTONIC = "/opt/homebrew/bin/tectonic"

state = {}            # ten tep -> {version, ok, log, compiling, pdf}
lock = threading.Lock()


def tex_files():
    out = []
    for dp, dn, fn in os.walk(ROOT):
        dn[:] = [d for d in dn if not d.startswith(".")]
        out += [os.path.join(dp, f) for f in fn if f.endswith(".tex")]
    return sorted(out)


def compile_tex(path):
    name = os.path.relpath(path, ROOT)
    with lock:
        st = state.setdefault(name, {"version": 0, "ok": None, "log": "", "compiling": False})
        st["compiling"] = True
    t0 = time.time()
    p = subprocess.run([TECTONIC, "--outdir", os.path.dirname(path), path],
                       capture_output=True, text=True)
    log = (p.stdout + p.stderr).strip()
    with lock:
        st["ok"] = p.returncode == 0
        st["log"] = "\n".join(l for l in log.splitlines() if not l.startswith("note:"))
        st["compiling"] = False
        st["seconds"] = round(time.time() - t0, 1)
        st["pdf"] = os.path.splitext(path)[0] + ".pdf"
        st["version"] += 1
    print(f"[{time.strftime('%H:%M:%S')}] {name}: {'OK' if p.returncode == 0 else 'LOI'} "
          f"({st['seconds']}s)", flush=True)


def watcher():
    mtimes = {}
    while True:
        for f in tex_files():
            try:
                m = os.path.getmtime(f)
            except OSError:
                continue
            if mtimes.get(f) != m:
                mtimes[f] = m
                threading.Thread(target=compile_tex, args=(f,), daemon=True).start()
        time.sleep(0.5)


PAGE = r"""<!doctype html><html lang="vi"><head><meta charset="utf-8">
<title>Xem truoc LaTeX</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js"></script>
<style>
body{margin:0;background:#525659;font-family:-apple-system,system-ui,sans-serif}
#bar{position:sticky;top:0;z-index:2;display:flex;gap:10px;align-items:center;padding:8px 12px;
 background:#2b2b2b;color:#ddd;font-size:13px}
#bar select{font-size:13px}
#st{margin-left:auto}
.ok{color:#8fd18f}.err{color:#ff8a80}.busy{color:#ffd27f}
#log{display:none;white-space:pre-wrap;background:#3a1f1f;color:#ffd6d6;font:12px/1.4 ui-monospace,monospace;
 padding:10px 14px;margin:0}
#pages{display:flex;flex-direction:column;align-items:center;gap:14px;padding:16px 0 40px}
canvas{background:#fff;box-shadow:0 1px 6px rgba(0,0,0,.4);max-width:96vw;height:auto}
</style></head><body>
<div id="bar"><span>Tep</span><select id="sel"></select><span id="st">Dang tai...</span></div>
<pre id="log"></pre><div id="pages"></div>
<script>
pdfjsLib.GlobalWorkerOptions.workerSrc="https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js";
const sel=document.getElementById('sel'),st=document.getElementById('st'),logEl=document.getElementById('log'),pages=document.getElementById('pages');
let shown={}, cur=localStorage.getItem('texfile')||'';
sel.onchange=()=>{cur=sel.value;localStorage.setItem('texfile',cur);shown={};poll();};
async function render(name,ver){
  const y=window.scrollY;
  const doc=await pdfjsLib.getDocument({url:'/pdf?f='+encodeURIComponent(name)+'&v='+ver}).promise;
  const frag=document.createDocumentFragment();
  for(let i=1;i<=doc.numPages;i++){
    const pg=await doc.getPage(i),vp=pg.getViewport({scale:1.6}),c=document.createElement('canvas');
    c.width=vp.width;c.height=vp.height;c.style.width=(vp.width/1.6*1.25)+'px';
    await pg.render({canvasContext:c.getContext('2d'),viewport:vp}).promise;frag.appendChild(c);
  }
  pages.replaceChildren(frag);window.scrollTo(0,y);
}
async function poll(){
  try{
    const s=await (await fetch('/status')).json(), names=Object.keys(s).sort();
    if(sel.options.length!==names.length){sel.innerHTML=names.map(n=>`<option>${n}</option>`).join('');}
    if(!names.includes(cur))cur=names[0]||'';sel.value=cur;
    const x=s[cur];if(!x)return;
    if(x.compiling){st.className='busy';st.textContent='Dang bien dich...';return;}
    if(x.ok){
      logEl.style.display='none';
      if(shown[cur]!==x.version){shown[cur]=x.version;await render(cur,x.version);}
      st.className='ok';st.textContent='Da cap nhat '+new Date().toLocaleTimeString('vi-VN')+' ('+x.seconds+' giay)';
    }else{
      st.className='err';st.textContent='Loi bien dich, dang giu ban PDF cu';
      logEl.style.display='block';logEl.textContent=x.log;
    }
  }catch(e){st.className='err';st.textContent='Mat ket noi toi may chu xem truoc';}
}
setInterval(poll,800);poll();
</script></body></html>"""


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            return self._send(200, "text/html; charset=utf-8", PAGE.encode())
        if u.path == "/status":
            with lock:
                body = {k: {kk: vv for kk, vv in v.items() if kk != "pdf"} for k, v in state.items()}
            return self._send(200, "application/json", json.dumps(body).encode())
        if u.path == "/pdf":
            name = parse_qs(u.query).get("f", [""])[0]
            with lock:
                pdf = state.get(name, {}).get("pdf")
            if pdf and os.path.exists(pdf):
                return self._send(200, "application/pdf", open(pdf, "rb").read())
            return self._send(404, "text/plain", b"khong co pdf")
        self._send(404, "text/plain", b"khong tim thay")


if __name__ == "__main__":
    print(f"Theo doi: {ROOT}", flush=True)
    threading.Thread(target=watcher, daemon=True).start()
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
