"""
Module: port_scanner.py
========================
TCP (and optional UDP) port scanner with banner grabbing.

Features:
  - Threaded TCP connect scan
  - UDP scan (requires root/sudo)
  - Banner grabbing for open ports
  - Common port presets (top100, top1000)
  - CIDR / hostname resolution

Usage via toolkit:
    python toolkit.py portscan --target 192.168.1.1 --ports 1-1024 --banner --confirm
    python toolkit.py portscan --target 192.168.1.1 --ports top100 --confirm
"""

import socket
import threading
import time
import re
from datetime import datetime
from queue import Queue

# Well-known port → service name mapping
WELL_KNOWN = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}

TOP_100 = [
    21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,
    1723,3306,3389,5900,8080,8443,
    # extras
    20,69,79,88,119,123,137,138,161,162,194,389,
    636,989,990,1080,1194,1433,1521,2049,3268,3269,
    5432,5800,5985,6379,7001,8000,8008,8081,8888,9000,
    9090,9200,9300,10000,27017,49152,49153,49154,49155,
    49156,49157,50000,51000,
]

TOP_1000 = list(range(1, 1001))


def parse_ports(port_str: str) -> list[int]:
    """Parse port specification into a sorted list of ints."""
    if port_str == "top100":
        return sorted(set(TOP_100))
    if port_str == "top1000":
        return sorted(set(TOP_1000))

    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Attempt to grab a service banner from an open port."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            # Send HTTP GET for web ports; just listen for others
            if port in (80, 8080, 8000, 8008, 8081, 8888, 9000, 9090):
                s.sendall(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            elif port == 21:
                pass  # FTP sends banner on connect
            elif port == 22:
                pass  # SSH sends banner on connect
            s.settimeout(timeout)
            banner = s.recv(1024).decode("utf-8", errors="replace").strip()
            # Limit to first line
            return banner.splitlines()[0][:200] if banner else ""
    except Exception:
        return ""


def tcp_scan_worker(ip: str, port_queue: Queue, results: list,
                    timeout: float, grab: bool, lock: threading.Lock):
    """Worker thread: dequeue ports and attempt TCP connect."""
    while True:
        port = port_queue.get()
        if port is None:
            break
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                banner = grab_banner(ip, port, timeout) if grab else ""
                service = WELL_KNOWN.get(port, socket.getservbyport(port, "tcp")
                                         if port < 1024 else "unknown")
                entry = {
                    "port": port,
                    "protocol": "tcp",
                    "state": "open",
                    "service": service,
                    "banner": banner,
                }
                with lock:
                    results.append(entry)
                    print(f"  [OPEN] {port}/tcp  {service:<12}  {banner[:60]}")
        except (ConnectionRefusedError, socket.timeout, OSError):
            pass  # Port closed or filtered
        finally:
            port_queue.task_done()


def udp_scan(ip: str, ports: list[int], timeout: float) -> list[dict]:
    """
    Rudimentary UDP scan: send empty datagram, wait for ICMP port-unreachable
    or a response. Results are unreliable without root privileges.
    """
    results = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(b"\x00" * 4, (ip, port))
                s.recvfrom(1024)
                service = WELL_KNOWN.get(port, "unknown")
                results.append({
                    "port": port,
                    "protocol": "udp",
                    "state": "open|filtered",
                    "service": service,
                    "banner": "",
                })
                print(f"  [OPEN|FILTERED] {port}/udp  {service}")
        except socket.timeout:
            # No response — could be open or filtered
            service = WELL_KNOWN.get(port, "unknown")
            results.append({
                "port": port,
                "protocol": "udp",
                "state": "open|filtered",
                "service": service,
                "banner": "",
            })
        except Exception:
            pass
    return results


def run(args) -> dict:
    """Entry point called by toolkit.py."""
    target = args.target
    timeout = getattr(args, "timeout", 1.0)
    threads = getattr(args, "threads", 100)
    grab = getattr(args, "banner", False)
    do_udp = getattr(args, "udp", False)
    verbose = getattr(args, "verbose", False)

    # Resolve hostname
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"❌ Cannot resolve host: {target}")
        return {}

    ports = parse_ports(getattr(args, "ports", "1-1024"))

    print(f"\n🔍 Port Scan: {target} ({ip})")
    print(f"   Ports   : {args.ports}  ({len(ports)} ports)")
    print(f"   Timeout : {timeout}s per port")
    print(f"   Threads : {threads}")
    print(f"   Banner  : {'yes' if grab else 'no'}")
    print(f"   Started : {datetime.now().isoformat()}\n")

    open_ports = []
    lock = threading.Lock()
    port_queue: Queue = Queue()

    for p in ports:
        port_queue.put(p)
    # Signal workers to stop
    for _ in range(threads):
        port_queue.put(None)

    workers = []
    for _ in range(threads):
        t = threading.Thread(
            target=tcp_scan_worker,
            args=(ip, port_queue, open_ports, timeout, grab, lock),
            daemon=True,
        )
        t.start()
        workers.append(t)

    port_queue.join()
    for t in workers:
        t.join()

    udp_results = []
    if do_udp:
        print("\n🔍 UDP Scan (common ports)...")
        udp_ports = [p for p in ports if p in WELL_KNOWN]
        udp_results = udp_scan(ip, udp_ports, timeout * 2)

    all_results = sorted(open_ports, key=lambda x: x["port"]) + udp_results

    print(f"\n{'─'*50}")
    print(f"  Scan complete. {len(open_ports)} TCP open port(s) found.")
    if do_udp:
        print(f"  {len(udp_results)} UDP port(s) open|filtered.")

    return {
        "module": "portscan",
        "target": target,
        "ip": ip,
        "scan_time": datetime.now().isoformat(),
        "ports_scanned": len(ports),
        "open_ports": all_results,
        "summary": {
            "tcp_open": len(open_ports),
            "udp_open_filtered": len(udp_results),
        },
    }
