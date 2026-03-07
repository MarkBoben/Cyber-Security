#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║           FILE INTEGRITY MONITOR — HashGuard v1.0           ║
║     Monitor file changes by calculating & comparing hashes  ║
╚══════════════════════════════════════════════════════════════╝
"""

import hashlib
import json
import os
import sys
import time
import argparse
from datetime import datetime
from pathlib import Path


# ─────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────
HASH_ALGORITHM   = "sha256"          # sha256 | md5 | sha1 | sha512
DEFAULT_DB       = "hashguard.json"  # where hashes are stored
WATCH_INTERVAL   = 5                 # seconds between checks in --watch mode
SEPARATOR        = "─" * 64


# ─────────────────────────────────────────────
#  HASHING
# ─────────────────────────────────────────────
def compute_hash(filepath: str, algorithm: str = HASH_ALGORITHM) -> str | None:
    """Compute the hash of a file. Returns None if the file cannot be read."""
    h = hashlib.new(algorithm)
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError) as e:
        print(f"  ⚠  Cannot read '{filepath}': {e}")
        return None


# ─────────────────────────────────────────────
#  DATABASE (JSON snapshot store)
# ─────────────────────────────────────────────
def load_db(db_path: str) -> dict:
    if os.path.exists(db_path):
        with open(db_path, "r") as f:
            return json.load(f)
    return {}


def save_db(db: dict, db_path: str) -> None:
    with open(db_path, "w") as f:
        json.dump(db, f, indent=2)


# ─────────────────────────────────────────────
#  CORE OPERATIONS
# ─────────────────────────────────────────────
def collect_files(paths: list[str]) -> list[str]:
    """Expand directories into individual file paths."""
    files = []
    for p in paths:
        if os.path.isfile(p):
            files.append(os.path.abspath(p))
        elif os.path.isdir(p):
            for root, _, fnames in os.walk(p):
                for name in fnames:
                    files.append(os.path.abspath(os.path.join(root, name)))
        else:
            print(f"  ⚠  Path not found: '{p}'")
    return files


def baseline(paths: list[str], db_path: str, algorithm: str) -> None:
    """Create or update a baseline snapshot of file hashes."""
    print(f"\n{'─'*64}")
    print("  📸  CREATING BASELINE SNAPSHOT")
    print(f"  Algorithm : {algorithm.upper()}")
    print(f"  Database  : {db_path}")
    print(SEPARATOR)

    db   = load_db(db_path)
    files = collect_files(paths)

    added = updated = skipped = 0
    for filepath in files:
        h = compute_hash(filepath, algorithm)
        if h is None:
            skipped += 1
            continue
        size = os.path.getsize(filepath)
        timestamp = datetime.now().isoformat(timespec="seconds")
        if filepath in db:
            updated += 1
            status = "↺  updated"
        else:
            added += 1
            status = "✚  added  "
        db[filepath] = {
            "hash":      h,
            "algorithm": algorithm,
            "size":      size,
            "baseline":  timestamp,
        }
        print(f"  {status}  {filepath}")
        print(f"           {algorithm.upper()}: {h}  ({size:,} bytes)")

    save_db(db, db_path)
    print(SEPARATOR)
    print(f"  ✅  Done — {added} added, {updated} updated, {skipped} skipped.")
    print(f"  💾  Snapshot saved to '{db_path}'\n")


def check(paths: list[str], db_path: str) -> bool:
    """Compare current file hashes against the stored baseline. Returns True if all OK."""
    print(f"\n{SEPARATOR}")
    print("  🔍  INTEGRITY CHECK")
    print(f"  Database : {db_path}")
    print(f"  Time     : {datetime.now().isoformat(timespec='seconds')}")
    print(SEPARATOR)

    db = load_db(db_path)
    if not db:
        print("  ⚠  No baseline found. Run with --baseline first.\n")
        return False

    # Determine scope
    if paths:
        files = collect_files(paths)
    else:
        files = list(db.keys())

    ok = modified = missing = new_files = 0
    alerts = []

    for filepath in files:
        if not os.path.exists(filepath):
            if filepath in db:
                missing += 1
                alerts.append(("🗑  DELETED ", filepath, db[filepath]["hash"], "—"))
            continue

        if filepath not in db:
            new_files += 1
            h = compute_hash(filepath, HASH_ALGORITHM)
            alerts.append(("🆕  NEW FILE", filepath, "—", h or "error"))
            continue

        algo    = db[filepath]["algorithm"]
        old_hash = db[filepath]["hash"]
        new_hash = compute_hash(filepath, algo)

        if new_hash is None:
            continue

        if new_hash != old_hash:
            modified += 1
            alerts.append(("⚠️  MODIFIED", filepath, old_hash, new_hash))
        else:
            ok += 1

    # Print results
    if not alerts:
        print(f"  ✅  All {ok} file(s) are UNCHANGED.")
    else:
        for label, fp, old_h, new_h in alerts:
            print(f"\n  {label}  {fp}")
            if old_h != "—":
                print(f"    OLD: {old_h}")
            if new_h != "—":
                print(f"    NEW: {new_h}")

    print(SEPARATOR)
    total = ok + modified + missing + new_files
    print(f"  📊  Summary — Total: {total} | OK: {ok} | "
          f"Modified: {modified} | Deleted: {missing} | New: {new_files}\n")

    return modified == 0 and missing == 0


def watch(paths: list[str], db_path: str, interval: int) -> None:
    """Continuously monitor files at a given interval."""
    print(f"\n  👁   WATCH MODE  (interval: {interval}s)  —  Press Ctrl+C to stop\n")
    try:
        while True:
            all_ok = check(paths, db_path)
            if not all_ok:
                print("  🔔  ALERT: Changes detected!\n")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n  🛑  Monitoring stopped.\n")


def list_baseline(db_path: str) -> None:
    """Display all files in the current baseline."""
    db = load_db(db_path)
    if not db:
        print("  ⚠  No baseline database found.\n")
        return

    print(f"\n{SEPARATOR}")
    print(f"  📋  BASELINE CONTENTS  —  {db_path}")
    print(SEPARATOR)
    for i, (fp, meta) in enumerate(db.items(), 1):
        print(f"  [{i:>3}]  {fp}")
        print(f"         {meta['algorithm'].upper()}: {meta['hash']}")
        print(f"         Size: {meta['size']:,} bytes  |  Captured: {meta['baseline']}")
    print(f"\n  Total: {len(db)} file(s)\n")


def remove_from_baseline(paths: list[str], db_path: str) -> None:
    """Remove specific files from the baseline database."""
    db = load_db(db_path)
    for p in paths:
        fp = os.path.abspath(p)
        if fp in db:
            del db[fp]
            print(f"  🗑  Removed: {fp}")
        else:
            print(f"  ⚠  Not in baseline: {fp}")
    save_db(db, db_path)


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hashguard",
        description="HashGuard — File Integrity Monitor using hash comparison",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python file_integrity_monitor.py --baseline /etc/nginx /var/www
  python file_integrity_monitor.py --check
  python file_integrity_monitor.py --watch --interval 10
  python file_integrity_monitor.py --list
  python file_integrity_monitor.py --baseline . --algorithm sha512 --db custom.json
        """
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--baseline", "-b", nargs="+", metavar="PATH",
                       help="Create/update baseline snapshot for given files/directories")
    group.add_argument("--check",    "-c", nargs="*", metavar="PATH",
                       help="Check integrity against baseline (all files if none specified)")
    group.add_argument("--watch",    "-w", nargs="*", metavar="PATH",
                       help="Continuously monitor files (uses --interval)")
    group.add_argument("--list",     "-l", action="store_true",
                       help="List all files in the current baseline")
    group.add_argument("--remove",   "-r", nargs="+", metavar="PATH",
                       help="Remove files from the baseline database")

    parser.add_argument("--db",        default=DEFAULT_DB,      metavar="FILE",
                        help=f"Path to hash database (default: {DEFAULT_DB})")
    parser.add_argument("--algorithm", default=HASH_ALGORITHM,
                        choices=["md5", "sha1", "sha256", "sha512"],
                        help=f"Hash algorithm (default: {HASH_ALGORITHM})")
    parser.add_argument("--interval", type=int, default=WATCH_INTERVAL, metavar="SECS",
                        help=f"Watch interval in seconds (default: {WATCH_INTERVAL})")
    return parser


def main():
    parser = build_parser()
    args   = parser.parse_args()

    if args.baseline:
        baseline(args.baseline, args.db, args.algorithm)

    elif args.check is not None:
        ok = check(args.check or [], args.db)
        sys.exit(0 if ok else 1)

    elif args.watch is not None:
        if not os.path.exists(args.db):
            print("  ⚠  No baseline found. Run --baseline first.")
            sys.exit(1)
        watch(args.watch or [], args.db, args.interval)

    elif args.list:
        list_baseline(args.db)

    elif args.remove:
        remove_from_baseline(args.remove, args.db)


if __name__ == "__main__":
    main()
