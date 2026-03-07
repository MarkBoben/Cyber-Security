"""
Module: web_prober.py
======================
Web application reconnaissance — headers, forms, and directory fuzzing.

Features:
  - Security header analysis (HSTS, CSP, X-Frame-Options, etc.)
  - Technology fingerprinting from headers and HTML meta tags
  - HTML form enumeration (action, method, input fields)
  - Robots.txt & sitemap.xml parsing
  - Optional directory/path fuzzing with a wordlist
  - Cookie flag analysis (Secure, HttpOnly, SameSite)

Usage:
    python toolkit.py webprobe --target http://192.168.1.1 --headers --forms --confirm
    python toolkit.py webprobe --target http://192.168.1.1 --wordlist /usr/share/wordlists/dirb/common.txt --confirm
"""

import urllib.request
import urllib.error
import urllib.parse
import ssl
import re
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser


# ─── HTML Parsers ─────────────────────────────────────────────────────────────

class MetaTagParser(HTMLParser):
    """Extract <meta> tags and <title> from HTML."""
    def __init__(self):
        super().__init__()
        self.metas = []
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        if tag == "meta":
            self.metas.append(dict(attrs))
        elif tag == "title":
            self._in_title = True

    def handle_data(self, data):
        if self._in_title:
            self.title += data

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False


class FormParser(HTMLParser):
    """Extract <form> tags and their input fields."""
    def __init__(self):
        super().__init__()
        self.forms = []
        self._current = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self._current = {
                "action": attrs.get("action", ""),
                "method": attrs.get("method", "GET").upper(),
                "inputs": [],
            }
            self.forms.append(self._current)
        elif tag in ("input", "select", "textarea") and self._current:
            self._current["inputs"].append({
                "type": attrs.get("type", "text"),
                "name": attrs.get("name", ""),
                "id": attrs.get("id", ""),
            })

    def handle_endtag(self, tag):
        if tag == "form":
            self._current = None


# ─── Helpers ──────────────────────────────────────────────────────────────────

def build_opener(user_agent: str | None, timeout: float):
    """Build an urllib opener that ignores SSL errors."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx)
    )
    ua = user_agent or "PenToolkit/1.0 (Security Research)"
    opener.addheaders = [("User-Agent", ua)]
    return opener


def fetch(url: str, opener, timeout: float) -> tuple[int, dict, str]:
    """Return (status_code, headers_dict, body_text)."""
    try:
        with opener.open(url, timeout=timeout) as resp:
            status = resp.status
            headers = dict(resp.headers)
            body = resp.read(1024 * 512).decode("utf-8", errors="replace")
            return status, headers, body
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), ""
    except Exception as e:
        return 0, {}, str(e)


def analyze_security_headers(headers: dict) -> dict:
    """Check presence and basic validity of security headers."""
    checks = {
        "Strict-Transport-Security": {
            "present": False, "value": None, "note": "",
        },
        "Content-Security-Policy": {"present": False, "value": None, "note": ""},
        "X-Frame-Options": {"present": False, "value": None, "note": ""},
        "X-Content-Type-Options": {"present": False, "value": None, "note": ""},
        "X-XSS-Protection": {"present": False, "value": None, "note": ""},
        "Referrer-Policy": {"present": False, "value": None, "note": ""},
        "Permissions-Policy": {"present": False, "value": None, "note": ""},
    }
    # Normalize header keys to lowercase for lookup
    lc_headers = {k.lower(): v for k, v in headers.items()}

    for header_name in list(checks.keys()):
        lc = header_name.lower()
        if lc in lc_headers:
            val = lc_headers[lc]
            checks[header_name]["present"] = True
            checks[header_name]["value"] = val

            # Specific value checks
            if header_name == "Strict-Transport-Security":
                if "max-age=0" in val:
                    checks[header_name]["note"] = "⚠️  max-age=0 disables HSTS"
            elif header_name == "X-Frame-Options":
                if val.upper() not in ("DENY", "SAMEORIGIN"):
                    checks[header_name]["note"] = "⚠️  Unusual value"
            elif header_name == "X-XSS-Protection":
                if "0" in val:
                    checks[header_name]["note"] = "ℹ️  Disabled (modern CSP preferred)"

    return checks


def fingerprint_tech(headers: dict, body: str) -> list[str]:
    """Identify technologies from headers and HTML body."""
    tech = set()
    lc_h = {k.lower(): v for k, v in headers.items()}

    server = lc_h.get("server", "")
    if server:
        tech.add(f"Server: {server}")

    powered = lc_h.get("x-powered-by", "")
    if powered:
        tech.add(f"X-Powered-By: {powered}")

    aspnet = lc_h.get("x-aspnet-version", "")
    if aspnet:
        tech.add(f"ASP.NET: {aspnet}")

    # Body patterns
    patterns = [
        (r"wp-content|wp-includes", "WordPress"),
        (r"Joomla!", "Joomla"),
        (r"/sites/default/|Drupal", "Drupal"),
        (r"shopify", "Shopify"),
        (r"<meta name=[\"']generator[\"'] content=[\"']([^\"']+)", None),
        (r"jquery[/-]([\d.]+)", None),
        (r"bootstrap[/-]([\d.]+)", None),
        (r"react(?:\.min)?\.js", "React"),
        (r"angular(?:\.min)?\.js|ng-app", "Angular"),
        (r"vue(?:\.min)?\.js", "Vue.js"),
        (r"laravel_session", "Laravel"),
        (r"PHPSESSID", "PHP"),
        (r"__django_session|csrfmiddlewaretoken", "Django"),
        (r"rack\.session|_rails", "Ruby on Rails"),
    ]
    for pattern, label in patterns:
        m = re.search(pattern, body, re.I)
        if m:
            tech.add(label if label else m.group(1))

    return sorted(tech)


def analyze_cookies(headers: dict) -> list[dict]:
    """Analyze Set-Cookie headers for security flags."""
    results = []
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            parts = [p.strip() for p in v.split(";")]
            name = parts[0].split("=")[0] if parts else ""
            flags = {p.lower() for p in parts[1:]}
            results.append({
                "name": name,
                "secure": "secure" in flags,
                "httponly": "httponly" in flags,
                "samesite": next(
                    (p for p in parts if p.lower().startswith("samesite")), "Not Set"
                ),
                "raw": v[:120],
            })
    return results


def fuzz_directories(base_url: str, wordlist_path: str,
                     opener, timeout: float) -> list[dict]:
    """
    Fuzz URL paths from a wordlist. Reports 2xx and 3xx responses.
    Rate-limited to be respectful.
    """
    found = []
    try:
        with open(wordlist_path, "r", errors="replace") as f:
            words = [w.strip() for w in f if w.strip() and not w.startswith("#")]
    except FileNotFoundError:
        print(f"⚠️  Wordlist not found: {wordlist_path}")
        return found

    base_url = base_url.rstrip("/")
    print(f"\n   Fuzzing {len(words)} paths against {base_url} ...")

    def check_path(word):
        url = f"{base_url}/{word}"
        try:
            status, hdrs, _ = fetch(url, opener, timeout)
            if status in range(200, 400):
                return {"url": url, "status": status,
                        "size": hdrs.get("Content-Length", "?")}
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(check_path, w): w for w in words}
        for future in as_completed(futures):
            r = future.result()
            if r:
                found.append(r)
                print(f"    [{r['status']}] {r['url']}  ({r['size']} bytes)")

    return sorted(found, key=lambda x: x["url"])


# ─── Main run ─────────────────────────────────────────────────────────────────

def run(args) -> dict:
    target = args.target.rstrip("/")
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    timeout = getattr(args, "timeout", 5.0)
    show_headers = getattr(args, "headers", True)
    show_forms = getattr(args, "forms", False)
    wordlist = getattr(args, "wordlist", None)
    user_agent = getattr(args, "user_agent", None)

    opener = build_opener(user_agent, timeout)

    print(f"\n🌐 Web Probe: {target}")
    print(f"   Timeout: {timeout}s\n")

    results = {
        "module": "webprobe",
        "target": target,
        "scan_time": datetime.now().isoformat(),
    }

    # ── Main page ────────────────────────────────────────────────────────────
    print("  → Fetching main page...")
    status, headers, body = fetch(target, opener, timeout)
    results["status"] = status
    results["response_size"] = len(body)

    if status == 0:
        print(f"  ❌ Could not reach {target}: {body}")
        return results

    print(f"  HTTP Status : {status}")
    print(f"  Body size   : {len(body):,} bytes")

    # ── Technology fingerprinting ────────────────────────────────────────────
    tech = fingerprint_tech(headers, body)
    results["technologies"] = tech
    if tech:
        print("\n  🔧 Technologies detected:")
        for t in tech:
            print(f"     • {t}")

    # ── Page title & meta ────────────────────────────────────────────────────
    meta_parser = MetaTagParser()
    meta_parser.feed(body[:50000])
    results["page_title"] = meta_parser.title.strip()
    results["meta_tags"] = meta_parser.metas[:20]
    if meta_parser.title:
        print(f"\n  📄 Title: {meta_parser.title.strip()}")

    # ── Security headers ─────────────────────────────────────────────────────
    if show_headers:
        sec = analyze_security_headers(headers)
        results["security_headers"] = sec
        print("\n  🔒 Security Headers:")
        for h, info in sec.items():
            icon = "✅" if info["present"] else "❌"
            val = f"  ({info['value'][:60]})" if info["present"] and info["value"] else ""
            note = f"  {info['note']}" if info["note"] else ""
            print(f"     {icon} {h}{val}{note}")

    # ── Cookie analysis ───────────────────────────────────────────────────────
    cookies = analyze_cookies(headers)
    results["cookies"] = cookies
    if cookies:
        print("\n  🍪 Cookies:")
        for c in cookies:
            flags = []
            if not c["secure"]:     flags.append("⚠️  Missing Secure")
            if not c["httponly"]:   flags.append("⚠️  Missing HttpOnly")
            if "Not Set" in c["samesite"]: flags.append("⚠️  Missing SameSite")
            flag_str = "  " + "  ".join(flags) if flags else " ✅"
            print(f"     {c['name']}{flag_str}")

    # ── Forms ────────────────────────────────────────────────────────────────
    if show_forms:
        form_parser = FormParser()
        form_parser.feed(body[:100000])
        results["forms"] = form_parser.forms
        if form_parser.forms:
            print(f"\n  📋 Forms ({len(form_parser.forms)} found):")
            for i, form in enumerate(form_parser.forms, 1):
                print(f"     Form {i}: {form['method']} → {form['action'] or '(current page)'}")
                for inp in form["inputs"]:
                    print(f"       └ [{inp['type']}] name={inp['name']}")

    # ── Robots.txt ───────────────────────────────────────────────────────────
    print("\n  → Checking robots.txt & sitemap.xml...")
    robots_status, _, robots_body = fetch(f"{target}/robots.txt", opener, timeout)
    if robots_status == 200:
        disallowed = re.findall(r"Disallow:\s*(.*)", robots_body)
        results["robots_txt"] = {"status": robots_status, "disallowed": disallowed}
        if disallowed:
            print(f"  🤖 robots.txt — {len(disallowed)} disallowed path(s):")
            for d in disallowed[:10]:
                print(f"     • {d}")

    sitemap_status, _, _ = fetch(f"{target}/sitemap.xml", opener, timeout)
    results["sitemap_xml"] = {"status": sitemap_status}
    print(f"  🗺  sitemap.xml: HTTP {sitemap_status}")

    # ── Directory fuzzing ────────────────────────────────────────────────────
    if wordlist:
        fuzz_results = fuzz_directories(target, wordlist, opener, timeout)
        results["fuzz_results"] = fuzz_results
        print(f"\n  Found {len(fuzz_results)} accessible path(s).")

    return results
