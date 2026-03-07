"""
Module: report_generator.py
=============================
Generates professional HTML, JSON, or plain-text reports from scan results.

Accepts:
  - A single JSON results file
  - A directory containing multiple JSON result files

Produces an HTML report with:
  - Executive summary
  - Per-module sections (port scan, service enumeration, web probe, cred check)
  - Color-coded severity indicators
  - Timestamp and target metadata

Usage:
    python toolkit.py report --input ./results/ --output pentest_report.html --title "Lab Audit"
    python toolkit.py report --input ./results/portscan_20240101.json --format json
"""

import json
import os
import glob
from datetime import datetime


SEVERITY_CSS = {
    "critical": "#d32f2f",
    "high":     "#f57c00",
    "medium":   "#fbc02d",
    "low":      "#388e3c",
    "info":     "#1976d2",
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f4f6f9; color: #222; }}
  .header {{ background: linear-gradient(135deg, #1a1a2e, #16213e); color: white;
             padding: 2rem 3rem; }}
  .header h1 {{ font-size: 2rem; letter-spacing: 1px; }}
  .header .meta {{ margin-top: .5rem; opacity: .7; font-size: .9rem; }}
  .warning {{ background: #fff3cd; border-left: 4px solid #ffc107;
              padding: 1rem 2rem; font-size: .9rem; color: #856404; }}
  .container {{ max-width: 1100px; margin: 2rem auto; padding: 0 1.5rem; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                   gap: 1rem; margin-bottom: 2rem; }}
  .stat-card {{ background: white; border-radius: 8px; padding: 1.2rem;
                box-shadow: 0 1px 4px rgba(0,0,0,.08); text-align: center; }}
  .stat-card .num {{ font-size: 2.5rem; font-weight: 700; }}
  .stat-card .label {{ color: #666; font-size: .85rem; margin-top: .3rem; }}
  .section {{ background: white; border-radius: 8px; padding: 1.5rem;
              box-shadow: 0 1px 4px rgba(0,0,0,.08); margin-bottom: 1.5rem; }}
  .section h2 {{ font-size: 1.2rem; border-bottom: 2px solid #eee;
                 padding-bottom: .5rem; margin-bottom: 1rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: .88rem; }}
  th {{ background: #f0f4f8; text-align: left; padding: .5rem .8rem;
        border-bottom: 2px solid #dde; }}
  td {{ padding: .45rem .8rem; border-bottom: 1px solid #eee; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  .badge {{ display: inline-block; border-radius: 4px; padding: 2px 8px;
            font-size: .75rem; font-weight: 600; color: white; }}
  .open {{ background: #388e3c; }}
  .filtered {{ background: #f57c00; }}
  .missing {{ background: #d32f2f; }}
  .present {{ background: #388e3c; }}
  .success {{ background: #388e3c; }}
  .fail {{ background: #9e9e9e; }}
  pre {{ background: #f4f6f9; padding: .8rem; border-radius: 4px;
         font-size: .8rem; white-space: pre-wrap; overflow-x: auto; }}
  .footer {{ text-align: center; color: #999; font-size: .8rem;
             margin: 2rem 0; padding-bottom: 2rem; }}
</style>
</head>
<body>
<div class="header">
  <h1>🛡 {title}</h1>
  <div class="meta">Generated: {generated} &nbsp;|&nbsp; PenToolkit v1.0</div>
</div>
<div class="warning">
  ⚠️ <strong>CONFIDENTIAL:</strong> This report contains sensitive security information.
  Handle according to your organization's data classification policy.
</div>
<div class="container">
{body}
</div>
<div class="footer">PenToolkit v1.0 &mdash; For authorized use only</div>
</body>
</html>"""


# ─── Section renderers ────────────────────────────────────────────────────────

def render_portscan(data: dict) -> str:
    ports = data.get("open_ports", [])
    target = data.get("target", "?")
    ip = data.get("ip", "?")
    scanned = data.get("ports_scanned", "?")
    scan_time = data.get("scan_time", "?")

    rows = ""
    for p in ports:
        banner = p.get("banner", "") or ""
        cls = "open" if p["state"] == "open" else "filtered"
        rows += (
            f"<tr><td>{p['port']}</td>"
            f"<td>{p['protocol'].upper()}</td>"
            f"<td><span class='badge {cls}'>{p['state']}</span></td>"
            f"<td>{p.get('service','')}</td>"
            f"<td><code>{banner[:80]}</code></td></tr>\n"
        )

    if not rows:
        rows = "<tr><td colspan='5' style='color:#999'>No open ports found.</td></tr>"

    return f"""
<div class="section">
  <h2>🔍 Port Scan — {target} ({ip})</h2>
  <p style="margin-bottom:1rem; color:#555; font-size:.9rem">
    Scanned {scanned} ports &nbsp;|&nbsp; {len(ports)} open &nbsp;|&nbsp; {scan_time}
  </p>
  <table>
    <tr><th>Port</th><th>Proto</th><th>State</th><th>Service</th><th>Banner</th></tr>
    {rows}
  </table>
</div>"""


def render_enumerate(data: dict) -> str:
    services = data.get("services", [])
    target = data.get("target", "?")

    rows = ""
    for svc in services:
        port = svc.get("port", "?")
        proto = svc.get("protocol", "?")
        version = (svc.get("version") or svc.get("software") or
                   svc.get("banner", "")[:80] or "—")

        # Security header summary for HTTP services
        extra = ""
        if "security_headers" in svc:
            missing = [k for k, v in svc["security_headers"].items()
                       if not v.get("present")]
            if missing:
                extra = f"<br><small style='color:#c62828'>Missing headers: {', '.join(missing)}</small>"

        rows += (
            f"<tr><td>{port}</td><td>{proto}</td>"
            f"<td>{version}{extra}</td></tr>\n"
        )

    if not rows:
        rows = "<tr><td colspan='3' style='color:#999'>No services found.</td></tr>"

    return f"""
<div class="section">
  <h2>🔬 Service Enumeration — {target}</h2>
  <table>
    <tr><th>Port</th><th>Protocol</th><th>Version / Info</th></tr>
    {rows}
  </table>
</div>"""


def render_webprobe(data: dict) -> str:
    target = data.get("target", "?")
    status = data.get("status", "?")
    title = data.get("page_title", "")
    tech = data.get("technologies", [])
    sec = data.get("security_headers", {})
    cookies = data.get("cookies", [])
    fuzz = data.get("fuzz_results", [])

    tech_list = "".join(f"<li>{t}</li>" for t in tech) or "<li>None detected</li>"

    sec_rows = ""
    for h, info in sec.items():
        cls = "present" if info["present"] else "missing"
        val = info.get("value", "") or ""
        note = info.get("note", "") or ""
        sec_rows += (
            f"<tr><td>{h}</td>"
            f"<td><span class='badge {cls}'>{'Present' if info['present'] else 'Missing'}</span></td>"
            f"<td>{val[:80]}{' — ' + note if note else ''}</td></tr>\n"
        )

    cookie_rows = ""
    for c in cookies:
        flags = []
        if not c["secure"]:   flags.append("⚠️ No Secure")
        if not c["httponly"]: flags.append("⚠️ No HttpOnly")
        if "Not Set" in str(c.get("samesite", "")): flags.append("⚠️ No SameSite")
        cookie_rows += (
            f"<tr><td><code>{c['name']}</code></td>"
            f"<td>{' '.join(flags) or '✅ OK'}</td></tr>\n"
        )

    fuzz_rows = ""
    for r in fuzz[:50]:
        fuzz_rows += (
            f"<tr><td>{r.get('status')}</td>"
            f"<td><code>{r.get('url')}</code></td>"
            f"<td>{r.get('size', '?')} bytes</td></tr>\n"
        )

    fuzz_section = ""
    if fuzz_rows:
        fuzz_section = f"""
        <h3 style="margin-top:1rem">Directory Fuzz Results</h3>
        <table>
          <tr><th>Status</th><th>URL</th><th>Size</th></tr>
          {fuzz_rows}
        </table>"""

    return f"""
<div class="section">
  <h2>🌐 Web Probe — {target}</h2>
  <p style="color:#555; font-size:.9rem; margin-bottom:1rem">
    Status: <strong>{status}</strong> &nbsp;|&nbsp; Title: <em>{title or '(none)'}</em>
  </p>

  <h3>Technologies</h3>
  <ul style="margin: .5rem 0 1rem 1.5rem; font-size:.9rem">{tech_list}</ul>

  <h3>Security Headers</h3>
  <table style="margin-bottom:1rem">
    <tr><th>Header</th><th>Status</th><th>Value</th></tr>
    {sec_rows}
  </table>

  {f'<h3>Cookies</h3><table><tr><th>Name</th><th>Flags</th></tr>{cookie_rows}</table>' if cookie_rows else ''}
  {fuzz_section}
</div>"""


def render_credcheck(data: dict) -> str:
    target = data.get("target", "?")
    port = data.get("port", "?")
    service = data.get("service", "?")
    attempts = data.get("attempts", 0)
    successful = data.get("successful", [])

    rows = ""
    for c in successful:
        rows += (
            f"<tr><td><span class='badge success'>✅ VALID</span></td>"
            f"<td><code>{c['username']}</code></td>"
            f"<td><code>{c['password']}</code></td></tr>\n"
        )

    if not rows:
        rows = "<tr><td colspan='3' style='color:#999'>No valid credentials found.</td></tr>"

    risk = ""
    if successful:
        risk = f"<p style='color:#c62828; font-weight:600; margin-top:.5rem'>⚠️ {len(successful)} valid credential(s) confirmed!</p>"

    return f"""
<div class="section">
  <h2>🔑 Credential Check — {target}:{port} ({service.upper()})</h2>
  <p style="color:#555; font-size:.9rem; margin-bottom:1rem">
    {attempts} attempt(s) tested &nbsp;|&nbsp; {len(successful)} success(es)
  </p>
  {risk}
  <table style="margin-top:.8rem">
    <tr><th>Result</th><th>Username</th><th>Password</th></tr>
    {rows}
  </table>
</div>"""


RENDERERS = {
    "portscan":  render_portscan,
    "enumerate": render_enumerate,
    "webprobe":  render_webprobe,
    "credcheck": render_credcheck,
}


# ─── Main run ─────────────────────────────────────────────────────────────────

def load_results(input_path: str) -> list[dict]:
    """Load one or more JSON result files."""
    results = []
    if os.path.isdir(input_path):
        files = glob.glob(os.path.join(input_path, "*.json"))
    else:
        files = [input_path]

    for f in sorted(files):
        try:
            with open(f) as fh:
                results.append(json.load(fh))
            print(f"  ✅ Loaded: {f}")
        except Exception as e:
            print(f"  ⚠️  Could not load {f}: {e}")
    return results


def build_summary(all_results: list[dict]) -> dict:
    summary = {
        "targets": set(),
        "open_ports": 0,
        "services": 0,
        "web_findings": 0,
        "valid_creds": 0,
    }
    for r in all_results:
        mod = r.get("module", "")
        target = r.get("target", "")
        if target:
            summary["targets"].add(target)
        if mod == "portscan":
            summary["open_ports"] += len(r.get("open_ports", []))
        elif mod == "enumerate":
            summary["services"] += len(r.get("services", []))
        elif mod == "webprobe":
            summary["web_findings"] += 1
        elif mod == "credcheck":
            summary["valid_creds"] += len(r.get("successful", []))
    summary["targets"] = list(summary["targets"])
    return summary


def run(args) -> dict:
    input_path = args.input
    output_file = getattr(args, "output", "report.html")
    fmt = getattr(args, "format", "html")
    title = getattr(args, "title", "Penetration Test Report")

    print(f"\n📊 Report Generator")
    print(f"   Input  : {input_path}")
    print(f"   Output : {output_file}")
    print(f"   Format : {fmt}\n")

    all_results = load_results(input_path)
    if not all_results:
        print("❌ No results to report.")
        return {}

    if fmt == "json":
        with open(output_file, "w") as f:
            json.dump(all_results, f, indent=2, default=str)
        print(f"\n✅ JSON report saved: {output_file}")
        return {"output": output_file}

    if fmt == "text":
        with open(output_file, "w") as f:
            f.write(f"{title}\n{'='*60}\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n\n")
            for r in all_results:
                f.write(json.dumps(r, indent=2, default=str))
                f.write("\n\n")
        print(f"\n✅ Text report saved: {output_file}")
        return {"output": output_file}

    # ── HTML ──────────────────────────────────────────────────────────────────
    summary = build_summary(all_results)

    summary_html = f"""
<div class="summary-grid">
  <div class="stat-card">
    <div class="num" style="color:#1976d2">{len(summary['targets'])}</div>
    <div class="label">Targets</div>
  </div>
  <div class="stat-card">
    <div class="num" style="color:#388e3c">{summary['open_ports']}</div>
    <div class="label">Open Ports</div>
  </div>
  <div class="stat-card">
    <div class="num" style="color:#7b1fa2">{summary['services']}</div>
    <div class="label">Services Found</div>
  </div>
  <div class="stat-card">
    <div class="num" style="color:#{'d32f2f' if summary['valid_creds'] else '388e3c'}">{summary['valid_creds']}</div>
    <div class="label">Valid Credentials</div>
  </div>
</div>"""

    sections_html = summary_html
    for r in all_results:
        mod = r.get("module", "")
        renderer = RENDERERS.get(mod)
        if renderer:
            sections_html += renderer(r)
        else:
            sections_html += f"""
<div class="section">
  <h2>Module: {mod}</h2>
  <pre>{json.dumps(r, indent=2, default=str)[:3000]}</pre>
</div>"""

    html = HTML_TEMPLATE.format(
        title=title,
        generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        body=sections_html,
    )

    with open(output_file, "w") as f:
        f.write(html)

    print(f"\n✅ HTML report saved: {output_file}")
    return {"output": output_file, "summary": summary}
