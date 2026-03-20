#!/usr/bin/env python3
"""
Safe wrapper around gp.jar that integrates with the card key blacklist.

Usage:
    python3 gp_helper.py --install <cap_file>
    python3 gp_helper.py --delete <package_aid>
    python3 gp_helper.py --list
    python3 gp_helper.py --key-check

Any unrecognized args are passed through to gp.jar.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "tests", "tests"))

from util.card_key_guard import CardKeyGuard, get_card_serial

DEFAULT_KEY = "404142434445464748494A4B4C4D4E4F"
DEFAULT_KEY_VER = "1"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
GP_JAR = os.environ.get("GP_JAR", os.path.join(SCRIPT_DIR, "gp.jar"))


def _get_gp_key(args):
    if args.gp_key:
        return args.gp_key
    key_file = os.path.join(SCRIPT_DIR, ".gp-key")
    if os.path.exists(key_file):
        with open(key_file) as f:
            return f.read().strip()
    return DEFAULT_KEY


def _get_gp_key_ver(args):
    if args.gp_key_ver:
        return str(args.gp_key_ver)
    return DEFAULT_KEY_VER


def _gp_cmd(args_list, key, key_ver):
    cmd = ["java", "-jar", GP_JAR, "--key", key, "--key-ver", key_ver]
    cmd.extend(args_list)
    return cmd


def _run_gp(args_list, key, key_ver, capture=False):
    cmd = _gp_cmd(args_list, key, key_ver)
    print(f"[gp] {' '.join(cmd)}", file=sys.stderr)
    if capture:
        result = subprocess.run(cmd, capture_output=True, timeout=60)
        return result
    else:
        subprocess.run(cmd, timeout=60)
        return None


def _parse_installed_packages(gp_output):
    """Parse gp.jar -l output to extract installed package AIDs."""
    packages = []
    for line in gp_output.split("\n"):
        line = line.strip()
        m = re.match(r"PKG:\s+([0-9A-Fa-f]+)", line)
        if m:
            packages.append(m.group(1).upper())
    return packages


def cmd_list(args):
    key = _get_gp_key(args)
    key_ver = _get_gp_key_ver(args)
    result = _run_gp(["-d", "--list"], key, key_ver, capture=True)
    if result.returncode != 0 and not args.force_key:
        stderr = result.stderr.decode()
        if "6982" in stderr or "security" in stderr.lower():
            guard = CardKeyGuard(force=False)
            guard.record_failure(key)
            print(
                f"\n[gp_helper] Authentication failed. Key {hashlib.sha256(key.encode()).hexdigest()[:16]} "
                f"has been blacklisted for this card to prevent lockout.",
                file=sys.stderr,
            )
            sys.exit(1)
    output = result.stdout.decode() + result.stderr.decode()
    print(output)
    return output


def cmd_install(args):
    key = _get_gp_key(args)
    key_ver = _get_gp_key_ver(args)
    guard = CardKeyGuard(force=args.force_key)
    guard.check_key(key)

    cap_file = args.install
    if not os.path.exists(cap_file):
        print(f"Error: CAP file not found: {cap_file}", file=sys.stderr)
        sys.exit(1)

    result = _run_gp(["-d", "--install", cap_file], key, key_ver, capture=True)
    output = result.stdout.decode() + result.stderr.decode()
    print(output)

    if result.returncode != 0:
        if "6982" in output or "security" in output.lower() or "authentication" in output.lower():
            guard.record_failure(key)
            print(
                f"\n[gp_helper] Install failed (authentication error). Key blacklisted for this card.",
                file=sys.stderr,
            )
        sys.exit(1)


def cmd_delete(args):
    key = _get_gp_key(args)
    key_ver = _get_gp_key_ver(args)
    guard = CardKeyGuard(force=args.force_key)
    guard.check_key(key)

    package_aid = args.delete
    result = _run_gp(["-d", "--delete", package_aid, "--force"], key, key_ver, capture=True)
    output = result.stdout.decode() + result.stderr.decode()
    print(output)

    if result.returncode != 0:
        if "6982" in output or "security" in output.lower():
            guard.record_failure(key)
            sys.exit(1)


def cmd_key_check(args):
    serial = get_card_serial()
    if serial:
        print(f"Card detected: {serial}")
    else:
        print("No card or reader detected.")
        sys.exit(1)

    guard = CardKeyGuard(force=True)
    guard.list_failures()


def cmd_key_clear(args):
    guard = CardKeyGuard(force=True)
    guard.clear_failures()


def cmd_is_installed(args):
    """Check if a package AID is installed. Exit 0 if yes, 1 if no."""
    key = _get_gp_key(args)
    key_ver = _get_gp_key_ver(args)
    guard = CardKeyGuard(force=args.force_key)
    guard.check_key(key)

    result = _run_gp(["-d", "--list"], key, key_ver, capture=True)
    output = result.stdout.decode() + result.stderr.decode()

    if result.returncode != 0:
        if "6982" in output or "security" in output.lower():
            guard.record_failure(key)
        sys.exit(1)

    packages = _parse_installed_packages(output)
    target = args.check_installed.upper()
    if target in packages:
        print(f"INSTALLED: {target}")
        sys.exit(0)
    else:
        print(f"NOT_INSTALLED: {target}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Safe gp.jar wrapper with key blacklist protection"
    )
    parser.add_argument("--gp-key", default=None, help="GP key (default: 4041...4F)")
    parser.add_argument("--gp-key-ver", type=int, default=None, help="GP key version (default: 1)")
    parser.add_argument("--force-key", action="store_true",
                        help="Bypass key blacklist (use with caution)")
    parser.add_argument("--install", metavar="CAP", help="Install CAP file")
    parser.add_argument("--delete", metavar="AID", help="Delete package by AID")
    parser.add_argument("--list", action="store_true", help="List installed packages")
    parser.add_argument("--key-check", action="store_true", help="Show card identity and failures")
    parser.add_argument("--key-clear", action="store_true", help="Clear key failures for current card")
    parser.add_argument("--check-installed", metavar="AID",
                        help="Check if package AID is installed (exit code 0/1)")
    args, remaining = parser.parse_known_args()

    if args.install:
        cmd_install(args)
    elif args.delete:
        cmd_delete(args)
    elif args.list:
        cmd_list(args)
    elif args.key_check:
        cmd_key_check(args)
    elif args.key_clear:
        cmd_key_clear(args)
    elif args.check_installed:
        cmd_is_installed(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
