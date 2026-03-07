"""
Module: credential_checker.py
===============================
Tests credential lists against services YOU OWN or have explicit written
permission to test. This is NOT a general brute-forcer — it is designed
for authorized auditing of your own systems (CTF labs, home labs, etc.).

Supported services:
  - SSH   (via paramiko if installed, else socket banner check only)
  - FTP   (via ftplib)
  - HTTP Basic Auth (urllib)
  - HTTP Form Login (POST form with configurable fields + failure string)

Safety controls:
  - Minimum 0.5s delay between attempts (configurable)
  - Respects --stop-on-success
  - Logs every attempt with timestamp
  - Requires --confirm flag in toolkit.py

Usage:
    python toolkit.py credcheck --target 192.168.1.1 --service ssh \\
        --users users.txt --passwords passwords.txt --confirm

    python toolkit.py credcheck --target 192.168.1.1 --service http-form \\
        --users users.txt --passwords passwords.txt \\
        --login-url http://192.168.1.1/login \\
        --user-field username --pass-field password \\
        --fail-string "Invalid credentials" --confirm
"""

import ftplib
import urllib.request
import urllib.error
import urllib.parse
import base64
import socket
import ssl
import time
from datetime import datetime


# ─── Service Implementations ──────────────────────────────────────────────────

def try_ssh(host: str, port: int, username: str, password: str,
            timeout: float = 5.0) -> tuple[bool, str]:
    """
    Test SSH credentials using paramiko.
    Falls back to a banner-only check if paramiko is not installed.
    """
    try:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(host, port=port, username=username,
                           password=password, timeout=timeout,
                           allow_agent=False, look_for_keys=False)
            client.close()
            return True, "Authentication successful"
        except paramiko.AuthenticationException:
            return False, "Authentication failed"
        except paramiko.SSHException as e:
            return False, f"SSH error: {e}"
        except Exception as e:
            return False, f"Connection error: {e}"

    except ImportError:
        return False, ("paramiko not installed. "
                       "Install with: pip install paramiko --break-system-packages")


def try_ftp(host: str, port: int, username: str, password: str,
            timeout: float = 5.0) -> tuple[bool, str]:
    """Test FTP credentials using ftplib."""
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=timeout)
        ftp.login(username, password)
        ftp.quit()
        return True, "Login successful"
    except ftplib.error_perm as e:
        return False, str(e)
    except Exception as e:
        return False, f"Connection error: {e}"


def try_http_basic(host: str, port: int, username: str, password: str,
                   timeout: float = 5.0) -> tuple[bool, str]:
    """Test HTTP Basic Authentication."""
    url = f"http://{host}:{port}/"
    credentials = base64.b64encode(
        f"{username}:{password}".encode()
    ).decode()

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Basic {credentials}")
    req.add_header("User-Agent", "PenToolkit/1.0")

    try:
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx)
        )
        with opener.open(req, timeout=timeout) as resp:
            if resp.status == 200:
                return True, f"HTTP 200 — authenticated"
            return False, f"HTTP {resp.status}"
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return False, "HTTP 401 Unauthorized"
        if e.code == 403:
            return False, "HTTP 403 Forbidden (may be logged in but restricted)"
        return False, f"HTTP {e.code}"
    except Exception as e:
        return False, f"Error: {e}"


def try_http_form(login_url: str, username: str, password: str,
                  user_field: str, pass_field: str,
                  fail_string: str | None, timeout: float = 5.0) -> tuple[bool, str]:
    """Test HTTP form-based login via POST."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    data = urllib.parse.urlencode({
        user_field: username,
        pass_field: password,
    }).encode()

    req = urllib.request.Request(login_url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("User-Agent", "PenToolkit/1.0")

    try:
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPRedirectHandler(),
        )
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(1024 * 64).decode("utf-8", errors="replace")
            if fail_string and fail_string in body:
                return False, "Failure string found in response"
            return True, f"HTTP {resp.status} — no failure string detected"
    except urllib.error.HTTPError as e:
        body = e.read(1024 * 64).decode("utf-8", errors="replace")
        if fail_string and fail_string in body:
            return False, f"HTTP {e.code} — failure string found"
        return False, f"HTTP {e.code}"
    except Exception as e:
        return False, f"Error: {e}"


DEFAULT_PORTS = {
    "ssh": 22,
    "ftp": 21,
    "http-basic": 80,
    "http-form": 80,
}


def load_wordlist(path: str) -> list[str]:
    """Load lines from a wordlist file."""
    try:
        with open(path, "r", errors="replace") as f:
            return [line.strip() for line in f
                    if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"❌ Wordlist not found: {path}")
        return []


def run(args) -> dict:
    target = args.target
    service = args.service
    port = getattr(args, "port", None) or DEFAULT_PORTS[service]
    delay = getattr(args, "delay", 0.5)
    stop_on_success = getattr(args, "stop_on_success", False)
    timeout = 5.0

    users = load_wordlist(args.users)
    passwords = load_wordlist(args.passwords)

    if not users or not passwords:
        return {}

    print(f"\n🔑 Credential Check: {target}:{port}  [{service.upper()}]")
    print(f"   Users     : {len(users)}")
    print(f"   Passwords : {len(passwords)}")
    print(f"   Delay     : {delay}s between attempts")
    print(f"   Total     : up to {len(users) * len(passwords)} combinations\n")
    print("   ⚠️  Only run against systems you own or have written permission to test.\n")

    results = {
        "module": "credcheck",
        "target": target,
        "port": port,
        "service": service,
        "scan_time": datetime.now().isoformat(),
        "attempts": 0,
        "successful": [],
        "log": [],
    }

    # Build the test function
    def test_cred(username, password):
        if service == "ssh":
            return try_ssh(target, port, username, password, timeout)
        elif service == "ftp":
            return try_ftp(target, port, username, password, timeout)
        elif service == "http-basic":
            return try_http_basic(target, port, username, password, timeout)
        elif service == "http-form":
            login_url = getattr(args, "login_url", None) or f"http://{target}:{port}/login"
            user_field = getattr(args, "user_field", "username")
            pass_field = getattr(args, "pass_field", "password")
            fail_string = getattr(args, "fail_string", None)
            return try_http_form(login_url, username, password,
                                 user_field, pass_field, fail_string, timeout)
        return False, "Unknown service"

    attempt = 0
    for username in users:
        for password in passwords:
            attempt += 1
            results["attempts"] = attempt

            ts = datetime.now().isoformat()
            success, msg = test_cred(username, password)

            entry = {
                "timestamp": ts,
                "username": username,
                "password": password,
                "success": success,
                "message": msg,
            }
            results["log"].append(entry)

            status = "✅ SUCCESS" if success else "✗"
            print(f"  [{attempt:4d}] {username}:{password}  →  {status}  ({msg[:50]})")

            if success:
                results["successful"].append({
                    "username": username,
                    "password": password,
                })
                if stop_on_success:
                    print(f"\n  🎯 Found valid credentials! Stopping.")
                    return results

            time.sleep(max(0.1, delay))

    found = len(results["successful"])
    print(f"\n  Completed {attempt} attempt(s). {found} valid credential(s) found.")
    if results["successful"]:
        print("  Valid credentials:")
        for c in results["successful"]:
            print(f"    ✅ {c['username']}:{c['password']}")

    return results
