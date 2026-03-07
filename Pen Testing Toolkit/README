[README.md](https://github.com/user-attachments/files/25816479/README.md)
# PenToolkit — Modular Penetration Testing Framework

> **⚠️ LEGAL NOTICE**
> This toolkit is intended **only** for authorized penetration testing, CTF
> competitions, and security education on systems you own or have **explicit
> written permission** to test. Unauthorized use against systems you do not own
> may violate computer crime laws (CFAA in the US, Computer Misuse Act in the UK,
> and equivalent statutes elsewhere). The authors accept **no liability** for
> misuse.

---

## Overview

PenToolkit is a pure-Python, modular security reconnaissance framework.
Every module outputs structured JSON results that feed into a polished HTML
report. The `--confirm` flag on every active scan module enforces a moment of
intentional authorization acknowledgment before any packets leave your machine.

```
pentoolkit/
├── toolkit.py                  # CLI entry-point & module router
├── modules/
│   ├── __init__.py
│   ├── port_scanner.py         # TCP/UDP port scanning + banner grab
│   ├── service_enumerator.py   # Protocol-level version detection
│   ├── web_prober.py           # Web app recon (headers, forms, fuzzing)
│   ├── credential_checker.py   # Authorized credential testing
│   └── report_generator.py     # HTML/JSON/text report generation
├── results/                    # Auto-created; stores JSON scan outputs
└── README.md
```

---

## Requirements

| Dependency    | Purpose                   | Install                              |
|---------------|---------------------------|--------------------------------------|
| Python ≥ 3.10 | Core runtime              | Built-in                             |
| paramiko      | SSH credential testing    | `pip install paramiko`               |

Everything else uses the Python standard library (`socket`, `ftplib`,
`urllib`, `ssl`, `concurrent.futures`, `threading`).

---

## Quick Start

```bash
# 1. Clone / download the toolkit
cd pentoolkit

# 2. (Optional) install paramiko for SSH testing
pip install paramiko --break-system-packages

# 3. Scan a target you OWN
python toolkit.py portscan --target 192.168.1.100 --ports top100 --banner --confirm

# 4. Enumerate services on open ports
python toolkit.py enumerate --target 192.168.1.100 --confirm

# 5. Web reconnaissance
python toolkit.py webprobe --target http://192.168.1.100 --headers --forms --confirm

# 6. Generate a report from all scan results
python toolkit.py report --input ./results/ --output pentest_report.html
```

Open `pentest_report.html` in any browser to view the combined report.

---

## Module Reference

### 1. `portscan` — Port Scanner

Threaded TCP connect scanner with optional UDP scan and banner grabbing.

```
python toolkit.py portscan [OPTIONS] --target <host> --confirm
```

| Option        | Default   | Description                                              |
|---------------|-----------|----------------------------------------------------------|
| `--target`    | required  | IP address or hostname                                   |
| `--ports`     | `1-1024`  | `1-65535`, `80,443,8080`, `top100`, `top1000`            |
| `--timeout`   | `1.0`     | Per-port TCP timeout in seconds                          |
| `--threads`   | `100`     | Concurrent scanning threads                              |
| `--banner`    | off       | Attempt service banner grab on open ports               |
| `--udp`       | off       | Also probe UDP (requires root/sudo)                      |

**Port presets:**
- `top100` — 100 most commonly seen ports
- `top1000` — ports 1–1000

**Example output (JSON):**
```json
{
  "module": "portscan",
  "target": "192.168.1.100",
  "ip": "192.168.1.100",
  "ports_scanned": 100,
  "open_ports": [
    {"port": 22, "protocol": "tcp", "state": "open",
     "service": "SSH", "banner": "SSH-2.0-OpenSSH_8.9p1"},
    {"port": 80, "protocol": "tcp", "state": "open",
     "service": "HTTP", "banner": ""}
  ]
}
```

---

### 2. `enumerate` — Service Enumerator

Performs protocol-specific probes on open ports to identify exact versions.

```
python toolkit.py enumerate [OPTIONS] --target <host> --confirm
```

| Option      | Default          | Description                                 |
|-------------|------------------|---------------------------------------------|
| `--target`  | required         | IP address or hostname                      |
| `--ports`   | common 25 ports  | Specific ports to probe                     |
| `--timeout` | `3.0`            | Probe timeout in seconds                    |

**Protocol probes implemented:**

| Protocol | Method                                                      |
|----------|-------------------------------------------------------------|
| HTTP/S   | HEAD request → Server header, X-Powered-By, security hdrs  |
| SSH      | Banner read → `SSH-2.0-OpenSSH_8.9p1 Ubuntu…`              |
| FTP      | Banner + anonymous login check                              |
| SMTP     | Banner + EHLO extension list                                |
| MySQL    | Handshake packet → version string                           |
| Redis    | `INFO server` → version, OS, auth required                  |
| Generic  | Raw banner grab with newline probe                          |

---

### 3. `webprobe` — Web Application Prober

Performs passive and light-active reconnaissance against web targets.

```
python toolkit.py webprobe [OPTIONS] --target <url> --confirm
```

| Option          | Default | Description                                           |
|-----------------|---------|-------------------------------------------------------|
| `--target`      | req.    | Full URL: `http://host` or `https://host`             |
| `--headers`     | off     | Display + analyze all response/security headers       |
| `--forms`       | off     | Enumerate HTML forms and their input fields           |
| `--wordlist`    | off     | Path to directory wordlist for path fuzzing           |
| `--timeout`     | `5.0`   | Request timeout in seconds                            |
| `--user-agent`  | auto    | Custom User-Agent string                              |

**Security headers checked:**
- `Strict-Transport-Security` (HSTS)
- `Content-Security-Policy`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `X-XSS-Protection`
- `Referrer-Policy`
- `Permissions-Policy`

**Cookie flags checked:** `Secure`, `HttpOnly`, `SameSite`

**Technology fingerprinting patterns:** WordPress, Joomla, Drupal, Shopify,
Laravel, Django, Rails, PHP, React, Angular, Vue.js, jQuery, Bootstrap, and more.

---

### 4. `credcheck` — Credential Checker

Tests username/password combinations against a service **you own**.

```
python toolkit.py credcheck [OPTIONS] --target <host> --service <svc> \
    --users users.txt --passwords passwords.txt --confirm
```

| Option             | Default       | Description                                  |
|--------------------|---------------|----------------------------------------------|
| `--target`         | required      | IP address or hostname                       |
| `--service`        | required      | `ssh`, `ftp`, `http-basic`, `http-form`      |
| `--users`          | required      | Path to username wordlist                    |
| `--passwords`      | required      | Path to password wordlist                    |
| `--port`           | protocol def. | Override default port                        |
| `--delay`          | `0.5`         | Seconds between each attempt (min 0.1)       |
| `--stop-on-success`| off           | Stop after first valid credential found      |
| `--login-url`      | —             | Full login URL (http-form only)              |
| `--user-field`     | `username`    | HTML form field name for username            |
| `--pass-field`     | `password`    | HTML form field name for password            |
| `--fail-string`    | —             | Response substring indicating login failure  |

**Creating wordlist files:**
```
# users.txt
admin
root
user
testuser

# passwords.txt
password
Password1
admin
changeme
```

**SSH example** (requires `pip install paramiko`):
```bash
python toolkit.py credcheck --target 192.168.1.100 --service ssh \
    --users users.txt --passwords passwords.txt \
    --delay 1.0 --stop-on-success --confirm
```

**HTTP form example:**
```bash
python toolkit.py credcheck --target 192.168.1.100 --service http-form \
    --login-url http://192.168.1.100/admin/login \
    --user-field email --pass-field pass \
    --fail-string "Login failed" \
    --users users.txt --passwords passwords.txt --confirm
```

---

### 5. `report` — Report Generator

Combines JSON scan outputs into a professional HTML report.

```
python toolkit.py report --input <path> --output report.html [OPTIONS]
```

| Option      | Default               | Description                              |
|-------------|-----------------------|------------------------------------------|
| `--input`   | required              | JSON file or directory of JSON files     |
| `--output`  | `report.html`         | Output filename                          |
| `--format`  | `html`                | `html`, `json`, or `text`                |
| `--title`   | "Pentest Report"      | Report title                             |

---

## Global Options

```
python toolkit.py [--output-dir DIR] [--json] [--verbose] [--confirm] <module> ...
```

| Flag            | Description                                              |
|-----------------|----------------------------------------------------------|
| `--output-dir`  | Where to save JSON result files (default: `./results`)   |
| `--json`        | Also print results as JSON to stdout                     |
| `--verbose`     | Show tracebacks on errors                                |
| `--confirm`     | **Required** for active scanning modules                 |

---

## Extending the Toolkit

Each module follows a simple contract:

```python
# modules/my_module.py
def run(args) -> dict:
    """
    args: argparse.Namespace from toolkit.py
    Returns a dict of findings (serialized to JSON automatically)
    """
    ...
    return {"module": "my_module", "findings": [...]}
```

To register a new module:

1. Add `"mymodule": "modules.my_module"` to the `MODULES` dict in `toolkit.py`
2. Add an `argparse` subparser for it in `build_parser()`
3. (Optional) Add an HTML renderer to `report_generator.py`

---

## Typical Penetration Test Workflow

```
Phase 1 — Reconnaissance
  portscan    → discover attack surface
  enumerate   → identify service versions & misconfigs

Phase 2 — Web Reconnaissance
  webprobe    → find missing headers, exposed forms, hidden paths

Phase 3 — Credential Auditing (own systems only)
  credcheck   → verify default/weak credentials on services

Phase 4 — Reporting
  report      → combine all findings into stakeholder-ready HTML
```

---

## License & Ethics

This project is released for **educational and authorized security research
purposes only**. Key principles:

1. **Always get written permission** before scanning any target.
2. **Prefer passive recon** (webprobe headers) over active exploitation.
3. **Use minimum viable delay** in credcheck to avoid account lockouts.
4. **Treat results as confidential** — handle with your organization's data
   classification policy.
5. **Report vulnerabilities responsibly** — give vendors/owners time to fix
   before disclosure.

---

*Built with Python 3.10+ standard library. No external dependencies required
except `paramiko` for SSH testing.*
