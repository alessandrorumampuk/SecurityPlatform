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

from vrt_severity import grade_findings

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
  .settings input[type=number]{background:#0b0f14;border:1px solid #30363d;
    border-radius:6px;color:#e6edf3;padding:.2em .4em;width:70px;height:auto;
    font-size:.8rem}
  .settings .mode-row{display:flex;gap:18px;padding:2px 0 10px;
    border-bottom:1px solid #21262d;margin-bottom:6px}
  .settings .mode-row label{border:0;padding:0}
  .settings .mode-hint{color:#6e7681;font-size:.7rem;margin:0 0 .6em;
    line-height:1.45}
  .settings .hint{color:#6e7681;font-size:.7rem;margin:.5em 0 0}
  .tlist{font-family:ui-monospace,monospace;font-size:.72rem;color:#8b98a5;
    max-height:200px;overflow:auto;margin:.7em 0;padding:.7em .9em;
    background:#161b22;border-radius:8px;line-height:1.7}
  .tlist .ok{color:#3fb950}.tlist .err{color:#f85149}.tlist .run{color:#d29922}
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
  .f .ev .vvm{color:#ff7b72;background:rgba(248,81,73,.13);border-radius:4px;
    padding:0 .3em;font-weight:700}
  .f .tool{color:#6e7681;font-size:.7rem}
  .sev{display:inline-block;font-weight:700;font-size:.68rem;border-radius:5px;
       padding:0 .45em;margin:0 4px 0 6px;vertical-align:1px;cursor:help}
  .sev-P1{background:#f85149;color:#fff}
  .sev-P2{background:#d29922;color:#0b0f14}
  .sev-P3{background:#e3b341;color:#0b0f14}
  .sev-P4{background:#388bfd;color:#fff}
  .sev-P5{background:#6e7681;color:#fff}
  .sev-VARIES,.sev-INFO{background:#21262d;color:#8b949e;
       border:1px solid #30363d}
  .cand{opacity:.55;border-left-color:#d29922}
  .cand b{color:#d29922}
  .live{color:#d29922;font-style:italic;font-weight:400}
  .empty{color:#3fb950;font-size:.9rem}
  .meta{color:#6e7681;font-size:.75rem;margin-top:10px}
  .step{margin:10px 0 2px;font-size:.85rem}
  .step .num{color:#58a6ff;font-weight:700}
  .step .t{color:#8b949e;font-weight:600}
  .mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.78rem;
        color:#c9d1d9;word-break:break-all;padding:2px 0 2px 18px}
  .mono.dim{color:#6e7681}
  .mono.ok{color:#3fb950}
  .mono.bad{color:#d29922}
  .mono .en{color:#8b949e;font-style:italic}
  .showbtn{background:#21262d;color:#8b949e;border:1px solid #30363d;
    border-radius:6px;font-size:.68rem;padding:1px 8px;margin-left:8px;
    cursor:pointer;vertical-align:middle}
  .showbtn:hover{color:#c9d1d9;border-color:#8b949e}
  .mono .showbtn{font-size:.62rem;padding:0 6px;margin-left:10px;
    vertical-align:baseline}
  .raw{color:#79c0ff}
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
    <div class="mode-row">
      <label><input type="radio" name="mode" value="single" checked> <b>Single Shot</b></label>
      <label><input type="radio" name="mode" value="automation"> <b>Automation</b></label>
    </div>
    <p class="mode-hint" id="modehint"></p>
    <label id="maxw" style="display:none">Max subdomains&nbsp;
      <input type="number" id="max_subs" value="50" min="0" max="10000">&nbsp;
      <span class="hint" style="margin:0">0 = all discovered</span></label>
    <label><input type="checkbox" id="ck_all" checked> <b>All</b></label>
    <label><input type="checkbox" value="xss"> Cross-Site Scripting (XSS)</label>
    <label><input type="checkbox" value="csrf"> Cross-Site Request Forgery (CSRF)</label>
    <label><input type="checkbox" value="blh"> Broken Link Hijacking</label>
    <label><input type="checkbox" value="info_disclosure"> Information Disclosure</label>
    <label><input type="checkbox" value="dirlist"> Directory Listing</label>
    <p class="hint">Unchecking All lets you pick detectors individually.
      BLH only mines social links — no profile verification.</p>
  </div>
  <div id="status"></div>
</div>
<div id="result">
  <div class="card"><b>Annotated screenshot</b><br>
    <img id="shot" alt="VVM screenshot"></div>
  <div class="card" id="findings"></div>
  <div class="card" id="xss_steps"></div>
  <div class="meta" id="meta"></div>
</div>
<script>
const esc=s=>String(s).replace(/[&<>"']/g,
  c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
// vvmXXXXXX / vvm{id} is the verification marker injected by
// recommend_payload.py — inert evidence anchor, not part of the exploit.
// Highlight it so it reads as an artifact (strip it when reusing payloads).
const hl=s=>esc(s).replace(/vvm[a-z]{6}|vvm{id}/g,'<span class="vvm">$&</span>');
// one delegated toggle for every .showbtn — 'Show the Process' targets an
// element by id (data-t); per-item Show flips its next sibling .raw span
document.addEventListener('click',e=>{
  const b=e.target.closest('.showbtn');if(!b)return;
  const r=b.dataset.t?document.getElementById(b.dataset.t):b.nextElementSibling;
  if(!r)return;
  const on=r.style.display==='none';
  r.style.display=on?'':'none';
  b.textContent=on?(b.dataset.on||'Hide'):(b.dataset.off||'Show');
});
const tg=document.getElementById('tg'),st=document.getElementById('st'),
      all=document.getElementById('ck_all');
tg.onclick=()=>{st.classList.toggle('open');tg.classList.toggle('open')};
const boxes=[...document.querySelectorAll('.settings input[type=checkbox]')].filter(c=>c.id!=='ck_all');
boxes.forEach(b=>b.onchange=()=>{ if(b.checked) all.checked=false;
  if(!boxes.some(x=>x.checked)) all.checked=true; });
all.onchange=()=>{ if(all.checked) boxes.forEach(b=>b.checked=false); };

const radios=[...document.querySelectorAll('input[name=mode]')],
      maxw=document.getElementById('maxw'),
      modehint=document.getElementById('modehint'),
      maxSubs=document.getElementById('max_subs');
const modeVal=()=>radios.find(r=>r.checked).value;
function refreshMode(){
  const a=modeVal()==='automation';
  maxw.style.display=a?'flex':'none';
  modehint.textContent=a
    ?'Automation: subdomain_finder enumerates *.domain, then every checked detector scans each resolving host (3 parallel). BLH-only uses its own crawler enumeration.'
    :'Single Shot: VVM maps the one target page, then runs the checked detectors on it.';
}
radios.forEach(r=>r.onchange=refreshMode);refreshMode();

let poll=null;
document.getElementById('f').onsubmit=async e=>{
  e.preventDefault();
  const url=document.getElementById('url').value.trim();
  const skills=all.checked?[]:boxes.filter(b=>b.checked).map(b=>b.value);
  const mode=modeVal(),max_subs=Math.max(0,parseInt(maxSubs.value)||0);
  document.getElementById('go').disabled=true;
  document.getElementById('result').style.display='none';
  const S=document.getElementById('status');
  S.innerHTML='<span class="spin"></span>Scanning — detectors are running…';
  const r=await fetch('/scan',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({url,skills,mode,max_subs})});
  const j=await r.json();
  if(j.error){S.textContent=j.error;document.getElementById('go').disabled=false;return;}
  poll=setInterval(()=>tick(j.job),2000);
};
function renderResults(j,live){
  const shotCard=document.getElementById('shot').parentElement;
  shotCard.style.display=j.image?'block':'none';
  if(j.image)document.getElementById('shot').src='/out/'+j.image+'?t='+Date.now();
  const F=document.getElementById('findings');
  const X=document.getElementById('xss_steps');
  const finds=j.findings||[];
  const tr=j.xss_trace||[];
  // trace card defaults to hidden; preserve the user's toggle across the
  // 2s re-renders (button label is rebuilt each time, so read current state)
  const procOpen=X.dataset.init&&X.style.display!=='none';
  let h='<b>Findings</b>'+(live?' <span class="live">· live — scan still running</span>':'');
  if(tr.length)h+=`<button class="showbtn" data-t="xss_steps" data-off="Show the Process" data-on="Hide the Process">${procOpen?'Hide':'Show'} the Process</button>`;
  if(j.targets&&j.targets.length){
    h+='<div class="tlist">'+j.targets.map(t=>
      `<div class="${t.status==='done'?'ok':t.status==='error'?'err':'run'}">`+
      `${esc(t.host)} — ${esc(t.status)}${t.verified?' · '+t.verified+' verified':''}</div>`
    ).join('')+'</div>';
  }
  if(!finds.length)h+='<p class="empty">No verified vulnerabilities found.</p>';
  else{
    const sc={};finds.forEach(f=>{if(f.severity)sc[f.severity]=(sc[f.severity]||0)+1});
    const tally=['P1','P2','P3','P4','P5','VARIES','INFO']
      .filter(s=>sc[s]).map(s=>`<span class="sev sev-${s}">${s}</span>×${sc[s]}`).join(' ');
    if(tally)h+='<div style="margin:.35em 0 .1em">'+tally+'</div>';
  }
  finds.forEach(f=>{
    const sev=f.severity?`<span class="sev sev-${esc(f.severity)}" title="${
      esc((f.vrt&&f.vrt.name)||'')}${(f.vrt&&f.vrt.variant)?' — '+esc(f.vrt.variant):''}${
      f.basis?'&#10;'+esc(f.basis):''}">${esc(f.severity)}</span>`:'';
    h+=`<div class="f ${f.status==='verified'?'':'cand'}">
      <b>${esc(f.status).toUpperCase()}</b>${sev} — ${esc(f.vuln)}
      <span class="tool">[${esc(f.tool||'surface')}${f.host?' @ '+esc(f.host):''}]</span>
      <div class="ev">${hl(f.evidence||'')}</div></div>`;});
  F.innerHTML=h;
  if(tr.length){
    let xh='<b>XSS bypass trace</b><div class="hint" style="margin:0 0 4px">how the pipeline probed the filter and picked the payload</div>';
    tr.forEach((s,i)=>{
      xh+=`<div class="step"><span class="num">${i+1}.</span> <span class="t">${esc(s.t)}</span>`;
      if(s.d)xh+=`<div class="mono">${hl(s.d)}</div>`;
      (s.items||[]).forEach(it=>{
        const cls=it.ok===false?'bad':it.ok===true?'ok':'dim';
        const extra=it.g!==undefined&&it.g!==it.e
          ?` <span class="en">→ ${hl(String(it.g))}</span>`:'';
        const tech=it.e&&it.g===undefined?` <span class="en">${esc(it.e)}</span>`:'';
        // raw injected text — char verdicts carry it in e; keyword mask
        // items carry it in raw (items_json map built server-side)
        const raw=it.raw!==undefined?it.raw:(it.g!==undefined?it.e:undefined);
        const rb=raw!==undefined&&raw!==''
          ?`<button class="showbtn">Show</button><span class="raw" style="display:none"> ${hl(String(raw))}</span>`:'';
        xh+=`<div class="mono ${cls}">${esc(String(it.n??''))}${extra}${tech}${rb}</div>`;
      });
      (s.verify||[]).forEach(v=>{
        xh+=`<div class="mono ${v.g==='V'?'ok':'bad'}">[${esc(v.g)}] ${hl(v.p||'')}`+
            (v.e?` <span class="en">— ${esc(v.e)}</span>`:'')+'</div>';
      });
      xh+='</div>';
    });
    X.innerHTML=xh;
    if(!X.dataset.init){X.style.display='none';X.dataset.init='1';}
  }else{X.style.display='none';}
  document.getElementById('meta').textContent= j.targets&&j.targets.length
    ?`${j.nodes!=null?j.nodes:j.targets.length} hosts scanned · ${j.elements||0} subdomains discovered${j.elapsed!=null?' · '+j.elapsed+'s':''}`
    :`${j.elements||0} elements mapped · ${j.nodes||0} nodes / ${j.edges||0} edges${j.elapsed!=null?' · '+j.elapsed+'s':''}`;
  document.getElementById('result').style.display='block';
}
async function tick(job){
  const j=await (await fetch('/status/'+job)).json();
  const S=document.getElementById('status');
  if(j.status==='running'){
    S.innerHTML='<span class="spin"></span>'+esc(j.stage||'Scanning — detectors are running…');
    if((j.targets&&j.targets.length)||(j.findings&&j.findings.length))
      renderResults(j,true);
    return;
  }
  clearInterval(poll);document.getElementById('go').disabled=false;
  if(j.status==='error'){S.textContent='Scan failed: '+(j.error||'unknown');return;}
  S.textContent='Done.';
  renderResults(j,false);
  document.getElementById('result').scrollIntoView({behavior:'smooth'});
}
</script></body></html>"""


_STAGE_RE = re.compile(r"\[([a-z_]+)(?::[^\]]+)?\]\s*(.*)")
_STAGE_LABEL = {"xss": "XSS", "csrf": "CSRF", "blh": "Broken Link Hijacking",
                "info_disclosure": "Information Disclosure",
                "dirlist": "Directory Listing",
                "auto": "Automation", "subdomain": "Subdomain Finder"}


XSS_LOG = BASE / "log"


def _xss_trace(t0):
    """Rebuild the bypass narrative from artifacts the xss pipeline left
    in log/ since the job started: probe strings, char/keyword verdicts,
    generated candidates, per-payload V/R grades. Read-only — the skill
    scripts are untouched."""
    steps = []
    try:
        def newest(suffix):
            c = [p for p in XSS_LOG.glob(f"*{suffix}")
                 if p.stat().st_mtime >= t0]
            return max(c, key=lambda p: p.stat().st_mtime) if c else None

        def html_meta(path):
            meta = {}
            # the 'newline' probe item puts a literal \n inside input_sent,
            # so that one comment can span two physical lines — match the
            # opening tag and grab the value up to '-->' or end of line.
            for line in path.read_text(
                    encoding="utf-8", errors="replace").splitlines()[:25]:
                m = re.match(r"<!-- (\w+):\s*(.*)$", line)
                if m:
                    meta[m.group(1)] = re.sub(r"\s*-->\s*$", "",
                                              m.group(2))
            return meta

        def mask_from(analysis):
            mask = {}
            for r in analysis.get("results", []):
                n = r.get("character_name")
                if not n:
                    continue
                mask[n] = mask.get(n, True) and bool(r.get("passed"))
            return mask

        # 1-2. char probe + per-char verdicts
        hp, ra = newest("xss.html"), newest("xss_reflection_analysis.json")
        if hp:
            steps.append({"t": "Char probe — marker-bounded items sent",
                          "d": html_meta(hp).get("input_sent", "")})
        if ra:
            d = json.loads(ra.read_text(encoding="utf-8", errors="replace"))
            r_list = d.get("results", [])
            first_rid = (r_list[0].get("reflection_index", 1)
                         if r_list else 1)
            items = [
                {"n": r.get("character_name"), "e": r.get("expected"),
                 "g": r.get("got_back"), "ok": bool(r.get("passed"))}
                for r in r_list
                if r.get("reflection_index") == first_rid]
            steps.append({"t": "Char verdicts — what the filter did",
                          "items": items})
        # 3-4. keyword probe + mask
        kp, ka = newest("xss_keywords.html"), \
            newest("xss_keyword_analysis.json")
        items_map = {}
        if kp:
            km = html_meta(kp)
            steps.append({"t": "Keyword probe — junction/shape items sent",
                          "d": km.get("input_sent", "")})
            try:
                items_map = {n: t for n, t in json.loads(
                    km.get("items_json") or "[]")}
            except Exception:
                pass
        if ka:
            d = json.loads(ka.read_text(encoding="utf-8", errors="replace"))
            mask = mask_from(d)
            got = {}
            for r in d.get("results", []):
                n = r.get("character_name")
                if n and r.get("got_back") is not None \
                        and r.get("got_back") != r.get("expected"):
                    got.setdefault(n, r["got_back"])
            steps.append({"t": "Keyword mask — signature survivors",
                          "items": [{"n": k, "ok": v,
                                     "raw": items_map.get(k),
                                     "g": got.get(k)}
                                    for k, v in mask.items()]})
        # 5-6. candidates + per-payload verification
        rec = newest("xss_recommendation.json")
        if rec:
            d = json.loads(rec.read_text(encoding="utf-8", errors="replace"))
            for refl in d.get("reflections", []):
                ctx = refl.get("context", "?")
                steps.append({"t": f"Candidates — grammar output (ctx={ctx})",
                              "items": [{"n": c.get("payload"),
                                         "e": c.get("technique")}
                                        for c in refl.get("candidates", [])]})
                ver = [{"g": v.get("confidence"), "p": v.get("payload"),
                        "e": v.get("evidence")}
                       for v in (refl.get("verification") or [])]
                if ver:
                    steps.append({"t": f"Verify — marker-in-DOM (ctx={ctx})",
                                  "verify": ver})
    except Exception:
        pass
    return steps


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


def _present(findings):
    """Grade each flat finding against the Bugcrowd VRT (vrt_severity.py)
    and return the UI-facing projection -- verified first, then P1->P5."""
    return [{"vuln": f.get("vuln"), "status": f.get("status"),
             "evidence": f.get("evidence"), "tool": f.get("tool"),
             "host": f.get("host"), "severity": f.get("severity"),
             "vrt": f.get("vrt"), "basis": f.get("basis")}
            for f in grade_findings(findings)]


def _run_job(job, url, skills, mode="single", max_subs=0):
    """Single Shot: run vvm.py as a subprocess; stream stdout so the UI
    can show which stage/skill is currently running.
    Automation defers to _run_automation."""
    if mode == "automation":
        return _run_automation(job, url, skills, max_subs)
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
    JOBS[job].update(
        status="done", image=png.name,
        xss_trace=_xss_trace(t0),
        findings=_present(graph.get("findings", [])),
        elements=graph.get("meta", {}).get("elements", 0),
        nodes=len(graph.get("nodes", [])),
        edges=len(graph.get("edges", [])),
        elapsed=int(time.time() - t0))


def _run_automation(job, url, skills, max_subs):
    """Automation mode: auto_hunt.py enumerates *.domain via
    find_subdomains.py (one JSON log), then runs the checked skill
    detectors on every resolving host, bounded-parallel -- no VVM
    browser/screenshot stage. stdout is streamed so the UI can show
    which host/skill is currently running."""
    t0 = time.time()
    out_json = OUT_DIR / f"{job}-auto.json"
    argv = [sys.executable, "-u", str(BASE / "auto_hunt.py"),
            "--url", url, "--out", str(out_json), "--workers", "3"]
    if skills:
        argv += ["--skills", ",".join(skills)]
    if max_subs:
        argv += ["--max-hosts", str(max_subs)]
    env = dict(os.environ, PYTHONUNBUFFERED="1")
    JOBS[job]["stage"] = "Subdomain Finder — enumerating subdomains…"
    log = []
    try:
        p = subprocess.Popen(argv, cwd=str(BASE), env=env,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT,
                             text=True, bufsize=1)
        deadline = t0 + 14400  # automation can legitimately run for hours
        for line in p.stdout:
            log.append(line)
            stage = _stage_from(line)
            if stage:
                JOBS[job]["stage"] = stage
            if time.time() > deadline:
                p.kill()
                JOBS[job].update(status="error",
                                 error="automation timed out (4h)",
                                 log="".join(log))
                return
        rc = p.wait(timeout=30)
        JOBS[job]["log"] = "".join(log)[-4000:]
        if rc != 0 or not out_json.exists():
            JOBS[job].update(status="error",
                             error=JOBS[job]["log"][-800:] or "no output")
            return
    except Exception as e:
        JOBS[job].update(status="error", error=str(e), log="".join(log))
        return

    try:
        data = json.loads(out_json.read_text(encoding="utf-8",
                                             errors="replace"))
    except Exception as e:
        JOBS[job].update(status="error",
                         error=f"bad auto_hunt output: {e}")
        return
    if data.get("error"):
        JOBS[job].update(status="error", error=data["error"],
                         log=(data.get("finder_log") or "")[-2000:])
        return

    JOBS[job].update(
        status="done", image=None,
        xss_trace=_xss_trace(t0),
        targets=data.get("targets", []),
        findings=_present(data.get("findings", [])),
        elements=data.get("subdomains_discovered", 0),
        nodes=data.get("hosts_scanned", 0), edges=0,
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
              if s in {"xss", "csrf", "blh", "info_disclosure", "dirlist"}]
    mode = body.get("mode") if body.get("mode") in {"single", "automation"} \
        else "single"
    try:
        max_subs = max(0, int(body.get("max_subs") or 0))
    except (TypeError, ValueError):
        max_subs = 0
    job = uuid.uuid4().hex[:12]
    JOBS[job] = {"status": "running", "started": time.time()}
    threading.Thread(target=_run_job,
                     args=(job, url, skills, mode, max_subs),
                     daemon=True).start()
    return jsonify(job=job)


@app.route("/status/<job>")
def status(job):
    j = JOBS.get(job)
    if not j:
        abort(404)
    out = {k: v for k, v in j.items() if k != "log"}
    # Automation writes a live snapshot after every finished host —
    # merge it into the running job so the UI shows findings early.
    if out.get("status") == "running":
        p = OUT_DIR / f"{job}-auto.json"
        try:
            live = json.loads(p.read_text(encoding="utf-8",
                                          errors="replace"))
            if live.get("targets"):
                out["targets"] = live["targets"]
            if live.get("findings"):
                out["findings"] = _present(live["findings"])
            if live.get("subdomains_discovered") is not None:
                out["elements"] = live["subdomains_discovered"]
        except Exception:
            pass
        # show the bypass trace while the pipeline is still writing
        # artifacts — each stage appears as soon as its log lands
        tr = _xss_trace(j.get("started", 0))
        if tr:
            out["xss_trace"] = tr
    return jsonify(out)


@app.route("/out/<name>")
def out_file(name):
    p = (OUT_DIR / name).resolve()
    if OUT_DIR not in p.parents or not p.exists():
        abort(404)
    return send_file(p)


if __name__ == "__main__":
    print("SecurityPlatform UI -> http://127.0.0.1:8766  (local use only)")
    app.run(host="127.0.0.1", port=8766)
