#!/usr/bin/env python3
"""
web.py -- SecurityPlatform web UI for VVM.

One URL input, a Settings drawer to pick which skill detectors run
(XSS / CSRF / Broken Link Hijacking / All), then the annotated VVM
screenshot plus the verified findings underneath.

The web layer only orchestrates: it shells out to vvm.py exactly like
the CLI does and renders the artifacts it produces (PNG + graph JSON).
No detection logic lives here.

    python3 web.py            # http://127.0.0.1:8766
Local training/testing use only -- scanning someone else's site needs
written authorization.
"""
import json
import os
import re
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

from flask import Flask, abort, jsonify, request, send_file

BASE = Path(__file__).resolve().parent
OUT_DIR = BASE / "log" / "web"
OUT_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
JOBS = {}  # job_id -> {status, image, findings, log, error, started}

PAGE = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecurityPlatform — Visual Vulnerability Mapping</title>
<style>
  :root{color-scheme:dark}
  *{box-sizing:border-box}
  body{margin:0;font-family:ui-sans-serif,system-ui,sans-serif;
       background:#0b0f14;color:#e6edf3;min-height:100vh}
  .wrap{max-width:640px;margin:0 auto;padding:0 20px}
  .hero{padding-top:16vh;text-align:center}
  h1{font-size:1.4rem;font-weight:600;margin:0 0 .4em}
  h1 .v{color:#f85149}
  .sub{color:#8b98a5;font-size:.8rem;margin-bottom:2em}
  .bar{display:flex;gap:8px}
  input[type=url]{flex:1;background:#0d1117;border:1px solid #30363d;
    border-radius:10px;padding:.9em 1em;color:#e6edf3;font-size:.95rem;outline:none}
  input[type=url]:focus{border-color:#388bfd;box-shadow:0 0 0 3px #388bfd33}
  button.scan{background:#f85149;border:0;color:#fff;font-weight:600;
    border-radius:10px;padding:.9em 1.4em;cursor:pointer;font-size:.9rem}
  button.scan:disabled{opacity:.5;cursor:wait}
  .toggle{margin:14px auto 0;display:inline-flex;align-items:center;gap:6px;
    color:#8b98a5;font-size:.8rem;cursor:pointer;user-select:none;
    border:1px solid #21262d;border-radius:999px;padding:.4em 1em;background:#0d1117}
  .toggle:hover{color:#e6edf3;border-color:#30363d}
  .arrow{display:inline-block;transition:transform .2s}
  .open .arrow{transform:rotate(90deg)}
  .settings{display:none;margin:14px auto 0;max-width:420px;text-align:left;
    background:#0d1117;border:1px solid #21262d;border-radius:12px;padding:14px 18px}
  .settings.open{display:block}
  .settings label{display:flex;align-items:center;gap:10px;padding:7px 0;
    font-size:.85rem;cursor:pointer}
  .settings label+label{border-top:1px solid #161b22}
  .settings input{accent-color:#f85149;width:15px;height:15px}
  .settings .hint{color:#6e7681;font-size:.7rem;margin:.5em 0 0}
  #status{margin-top:1.2em;font-size:.8rem;color:#8b98a5;min-height:1.2em}
  .spin{display:inline-block;width:.9em;height:.9em;border:2px solid #30363d;
    border-top-color:#f85149;border-radius:50%;animation:s .8s linear infinite;
    vertical-align:-2px;margin-right:6px}
  @keyframes s{to{transform:rotate(360deg)}}
  #result{max-width:1100px;margin:3em auto 4em;padding:0 20px;display:none}
  #result img{width:100%;border:1px solid #30363d;border-radius:12px;
    background:#fff;display:block}
  .card{background:#0d1117;border:1px solid #21262d;border-radius:12px;
    padding:18px 22px;margin-top:20px}
  .f{border-left:3px solid #f85149;padding:.5em 1em;margin:.7em 0;
    background:#161b22;border-radius:0 8px 8px 0}
  .f b{color:#f85149}
  .f .ev{color:#8b98a5;font-size:.78rem;word-break:break-all;
    font-family:ui-monospace,monospace;margin-top:2px}
  .f .tool{color:#6e7681;font-size:.7rem}
  .cand{opacity:.55;border-left-color:#d29922}
  .cand b{color:#d29922}
  .empty{color:#3fb950;font-size:.9rem}
  .meta{color:#6e7681;font-size:.75rem;margin-top:10px}
</style></head><body>
<div class="wrap hero">
  <h1>Security<span class="v">Platform</span></h1>
  <div class="sub">Visual Vulnerability Mapping — deterministic detectors only</div>
  <form id="f" class="bar">
    <input id="url" type="url" required placeholder="https://target-site.com"
           autocomplete="off">
    <button class="scan" id="go" type="submit">Scan</button>
  </form>
  <div class="toggle" id="tg"><span class="arrow">&#9656;</span> Settings</div>
  <div class="settings" id="st">
    <label><input type="checkbox" id="ck_all" checked> <b>All</b></label>
    <label><input type="checkbox" value="xss"> Cross-Site Scripting (XSS)</label>
    <label><input type="checkbox" value="csrf"> Cross-Site Request Forgery (CSRF)</label>
    <label><input type="checkbox" value="blh"> Broken Link Hijacking</label>
    <label><input type="checkbox" value="info_disclosure"> Information Disclosure</label>
    <p class="hint">Unchecking All lets you pick detectors individually.
      BLH runs a real browser per profile — it is the slowest.</p>
  </div>
  <div id="status"></div>
</div>
<div id="result">
  <div class="card"><b>Annotated screenshot</b><br>
    <img id="shot" alt="VVM screenshot"></div>
  <div class="card" id="findings"></div>
  <div class="meta" id="meta"></div>
</div>
<script>
const esc=s=>String(s).replace(/[&<>"']/g,
  c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const tg=document.getElementById('tg'),st=document.getElementById('st'),
      all=document.getElementById('ck_all');
tg.onclick=()=>{st.classList.toggle('open');tg.classList.toggle('open')};
const boxes=[...document.querySelectorAll('.settings input[type=checkbox]')].filter(c=>c.id!=='ck_all');
boxes.forEach(b=>b.onchange=()=>{ if(b.checked) all.checked=false;
  if(!boxes.some(x=>x.checked)) all.checked=true; });
all.onchange=()=>{ if(all.checked) boxes.forEach(b=>b.checked=false); };

let poll=null;
document.getElementById('f').onsubmit=async e=>{
  e.preventDefault();
  const url=document.getElementById('url').value.trim();
  const skills=all.checked?[]:boxes.filter(b=>b.checked).map(b=>b.value);
  document.getElementById('go').disabled=true;
  document.getElementById('result').style.display='none';
  const S=document.getElementById('status');
  S.innerHTML='<span class="spin"></span>Scanning — detectors are running…';
  const r=await fetch('/scan',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({url,skills})});
  const j=await r.json();
  if(j.error){S.textContent=j.error;document.getElementById('go').disabled=false;return;}
  poll=setInterval(()=>tick(j.job),2000);
};
async function tick(job){
  const j=await (await fetch('/status/'+job)).json();
  const S=document.getElementById('status');
  if(j.status==='running'){
    S.innerHTML='<span class="spin"></span>'+esc(j.stage||'Scanning — detectors are running…');
    return;
  }
  clearInterval(poll);document.getElementById('go').disabled=false;
  if(j.status==='error'){S.textContent='Scan failed: '+(j.error||'unknown');return;}
  S.textContent='Done.';
  document.getElementById('shot').src='/out/'+j.image+'?t='+Date.now();
  const F=document.getElementById('findings');
  let h='<b>Findings</b>';
  if(!j.findings.length)h+='<p class="empty">No verified vulnerabilities found.</p>';
  j.findings.forEach(f=>{
    h+=`<div class="f ${f.status==='verified'?'':'cand'}">
      <b>${esc(f.status).toUpperCase()}</b> — ${esc(f.vuln)}
      <span class="tool">[${esc(f.tool||'surface')}]</span>
      <div class="ev">${esc(f.evidence||'')}</div></div>`;});
  F.innerHTML=h;
  document.getElementById('meta').textContent=
    `${j.elements} elements mapped · ${j.nodes} nodes / ${j.edges} edges · ${j.elapsed}s`;
  document.getElementById('result').style.display='block';
  document.getElementById('result').scrollIntoView({behavior:'smooth'});
}
</script></body></html>"""


_STAGE_RE = re.compile(r"\[([a-z_]+)(?::[^\]]+)?\]\s*(.*)")
_STAGE_LABEL = {"xss": "XSS", "csrf": "CSRF", "blh": "Broken Link Hijacking",
                "info_disclosure": "Information Disclosure"}


def _stage_from(line):
    """Map a vvm.py stdout line to a human stage label, or None."""
    line = line.strip()
    if line.startswith("Skill detectors"):
        return "Detectors — starting selected skills"
    m = _STAGE_RE.match(line)
    if m:
        label = _STAGE_LABEL.get(m.group(1), m.group(1))
        rest = m.group(2).strip()
        return f"{label} — {rest[:90]}" if rest else label
    if "Verified vulnerabilities" in line or line.startswith(
            "No verified"):
        return "VVM — annotating screenshot"
    return None


def _run_job(job, url, skills):
    """Run vvm.py as a subprocess; stream stdout so the UI can show
    which stage/skill is currently running."""
    png = OUT_DIR / f"{job}.png"
    argv = [sys.executable, "-u", str(BASE / "vvm.py"), url,
            "-o", str(png), "--hunt"]
    if skills:
        argv += ["--skills", ",".join(skills)]
    env = dict(os.environ, PYTHONUNBUFFERED="1")
    t0 = time.time()
    JOBS[job]["stage"] = "VVM — loading page & mapping attack surface"
    log = []
    try:
        p = subprocess.Popen(argv, cwd=str(BASE), env=env,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT,
                             text=True, bufsize=1)
        deadline = t0 + 600
        for line in p.stdout:
            log.append(line)
            stage = _stage_from(line)
            if stage:
                JOBS[job]["stage"] = stage
            if time.time() > deadline:
                p.kill()
                JOBS[job].update(status="error",
                                 error="scan timed out (600s)", log="".join(log))
                return
        rc = p.wait(timeout=30)
        JOBS[job]["log"] = "".join(log)[-4000:]
        if rc != 0 or not png.exists():
            JOBS[job].update(status="error",
                             error=JOBS[job]["log"][-800:] or "no output")
            return
    except Exception as e:
        JOBS[job].update(status="error", error=str(e), log="".join(log))
        return

    graph = {}
    gp = OUT_DIR / f"{job}-graph.json"
    if gp.exists():
        try:
            graph = json.loads(gp.read_text(encoding="utf-8",
                                            errors="replace"))
        except Exception:
            pass
    finds = graph.get("findings", [])
    finds.sort(key=lambda f: f.get("status") != "verified")
    JOBS[job].update(
        status="done", image=png.name,
        findings=[{"vuln": f.get("vuln"), "status": f.get("status"),
                   "evidence": f.get("evidence"), "tool": f.get("tool")}
                  for f in finds],
        elements=graph.get("meta", {}).get("elements", 0),
        nodes=len(graph.get("nodes", [])),
        edges=len(graph.get("edges", [])),
        elapsed=int(time.time() - t0))


@app.route("/")
def index():
    return PAGE


@app.route("/scan", methods=["POST"])
def scan():
    body = request.get_json(silent=True) or {}
    url = (body.get("url") or "").strip()
    if not url.startswith(("http://", "https://")):
        return jsonify(error="URL must start with http:// or https://"), 400
    skills = [s for s in (body.get("skills") or [])
              if s in {"xss", "csrf", "blh", "info_disclosure"}]
    job = uuid.uuid4().hex[:12]
    JOBS[job] = {"status": "running", "started": time.time()}
    threading.Thread(target=_run_job, args=(job, url, skills),
                     daemon=True).start()
    return jsonify(job=job)


@app.route("/status/<job>")
def status(job):
    j = JOBS.get(job)
    if not j:
        abort(404)
    return jsonify({k: v for k, v in j.items() if k != "log"})


@app.route("/out/<name>")
def out_file(name):
    p = (OUT_DIR / name).resolve()
    if OUT_DIR not in p.parents or not p.exists():
        abort(404)
    return send_file(p)


if __name__ == "__main__":
    print("SecurityPlatform UI -> http://127.0.0.1:8766  (local use only)")
    app.run(host="127.0.0.1", port=8766)
