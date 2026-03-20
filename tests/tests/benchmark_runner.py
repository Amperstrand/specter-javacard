#!/usr/bin/env python3
"""
Real-card benchmark runner for all specter-javacard applets.
Flashes each applet via GlobalPlatformPro, runs timed operations,
and writes structured JSON results.

Usage:
    cd tests/tests
    TEST_MODE=card python3 benchmark_runner.py [options]

Options:
    --gp-jar PATH        Path to gp.jar (default: ../../gp.jar)
    --cap-dir PATH       Path to CAP files (default: ../../build/cap)
    --reader N           Reader index (default: 0)
    --gp-key HEX         GP key (default: 404142434445464748494A4B4C4D4E4F)
    --gp-key-ver N       GP key version (default: 1)
    --iterations N       Measurements per operation (default: 5)
    --warmup N           Warmup iterations (default: 2)
    --output PATH        Output JSON path (auto-generated if omitted)
    --applet NAME        Run only: teapot, memorycard, singleusekey, blindoracle
    --skip-flash         Skip flashing, assume applet is already installed
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from util.card import Card, ISOException, get_reader, get_connection
from util.securechannel import SecureChannel, SecureError
from util import secp256k1

APPLETS = {
    "teapot": {
        "aid": "B00B5111CA01",
        "cap": "TeapotApplet.cap",
        "package_aid": "B00B5111CA",
    },
    "memorycard": {
        "aid": "B00B5111CB01",
        "cap": "MemoryCardApplet.cap",
        "package_aid": "B00B5111CB",
    },
    "singleusekey": {
        "aid": "B00B5111CD01",
        "cap": "SingleUseKeyApplet.cap",
        "package_aid": "B00B5111CD",
    },
    "blindoracle": {
        "aid": "B00B5111CE01",
        "cap": "BlindOracleApplet.cap",
        "package_aid": "B00B5111CE",
    },
}

SELECT = b"\x00\xA4\x04\x00"
GET_RANDOM = b"\xB0\xB1\x00\x00"
GET_PUBKEY = b"\xB0\xB2\x00\x00"

SEED = bytes.fromhex(
    "ae361e712e3fe66c8f1d57192d80abe076137c917d37cee7da8ed152e993226d"
    "f0ced36f35c0967f96a5291f35035e87be9b3df626e6eb96ad2b59fbd9c503f4"
)
PATH_FULL = b"".join(
    p.to_bytes(4, "big")
    for p in [44 + 0x80000000, 0x80000000, 0x80000001, 0, 55]
)


def encode(data):
    return bytes([len(data)]) + data


def flash_applet(gp_jar, cap_path, aid, package_aid, gp_key, gp_key_ver):
    print(f"  Deleting existing package {package_aid}...")
    subprocess.run(
        ["java", "-jar", gp_jar, "--force", "--delete", package_aid,
         "--key", gp_key, "--key-ver", str(gp_key_ver)],
        capture_output=True, timeout=30,
    )
    print(f"  Installing {cap_path}...")
    result = subprocess.run(
        ["java", "-jar", gp_jar, "--install", cap_path,
         "--key", gp_key, "--key-ver", str(gp_key_ver)],
        capture_output=True, timeout=30,
    )
    if result.returncode != 0:
        print(f"  INSTALL FAILED: {result.stderr.decode()}")
        return False
    print(f"  Install OK")
    return True


def timed_op(card, apdu, warmup=2, iterations=5):
    results = []
    for i in range(warmup + iterations):
        try:
            t0 = time.perf_counter_ns()
            res = card.request(apdu)
            t1 = time.perf_counter_ns()
            if i >= warmup:
                results.append({
                    "duration_ms": (t1 - t0) / 1_000_000,
                    "response_len": len(res),
                    "success": True,
                })
        except ISOException as e:
            if i >= warmup:
                results.append({
                    "duration_ms": None,
                    "response_len": 0,
                    "success": False,
                    "error": str(e.code),
                })
        except Exception as e:
            if i >= warmup:
                results.append({
                    "duration_ms": None,
                    "response_len": 0,
                    "success": False,
                    "error": str(e),
                })
    if not results:
        return None
    durations = [r["duration_ms"] for r in results if r["duration_ms"] is not None]
    if durations:
        avg = sum(durations) / len(durations)
        mn = min(durations)
        mx = max(durations)
    else:
        avg = mn = mx = None
    return {
        "duration_ms": avg,
        "duration_min_ms": mn,
        "duration_max_ms": mx,
        "samples": len(results),
        "success": results[0]["success"],
        "response_len": results[0]["response_len"],
        "error": results[0].get("error"),
    }


def timed_fn(fn, warmup=2, iterations=5):
    results = []
    for i in range(warmup + iterations):
        try:
            t0 = time.perf_counter_ns()
            res = fn()
            t1 = time.perf_counter_ns()
            if i >= warmup:
                resp_len = len(res) if isinstance(res, (bytes, bytearray)) else 0
                results.append({
                    "duration_ms": (t1 - t0) / 1_000_000,
                    "response_len": resp_len,
                    "success": True,
                })
        except Exception as e:
            if i >= warmup:
                results.append({
                    "duration_ms": None,
                    "response_len": 0,
                    "success": False,
                    "error": str(e),
                })
    if not results:
        return None
    durations = [r["duration_ms"] for r in results if r["duration_ms"] is not None]
    if durations:
        avg = sum(durations) / len(durations)
        mn = min(durations)
        mx = max(durations)
    else:
        avg = mn = mx = None
    return {
        "duration_ms": avg,
        "duration_min_ms": mn,
        "duration_max_ms": mx,
        "samples": len(results),
        "success": results[0]["success"],
        "response_len": results[0]["response_len"],
        "error": results[0].get("error"),
    }


def run_benchmark(applet_name, card, args):
    info = APPLETS[applet_name]
    results = []

    def bench(operation, apdu):
        r = timed_op(card, apdu, args.warmup, args.iterations)
        if r is None:
            return
        r["applet"] = applet_name
        r["operation"] = operation
        results.append(r)

    def bench_fn(operation, fn):
        r = timed_fn(fn, args.warmup, args.iterations)
        if r is None:
            return
        r["applet"] = applet_name
        r["operation"] = operation
        results.append(r)

    aid = info["aid"]
    select_apdu = SELECT + encode(bytes.fromhex(aid))
    bench("select", select_apdu)

    if applet_name == "teapot":
        bench("get_default", b"\xB0\xA1\x00\x00")
        bench("put_small", b"\xB0\xA2\x00\x00\x02\x00\x80")
        bench("put_max", b"\xB0\xA2\x00\x00\xFE" + b"x" * 254)
        bench("get_after_put", b"\xB0\xA1\x00\x00")

    elif applet_name == "memorycard":
        bench("get_random", GET_RANDOM)
        bench("get_pubkey", GET_PUBKEY)

        def do_sc_open():
            sc = SecureChannel(card)
            sc.open()
            return b"ok"
        bench_fn("sc_open", do_sc_open)

        sc = SecureChannel(card)
        sc.open()
        bench_fn("sc_echo", lambda: sc.request(b"\x00\x00ping"))
        bench_fn("pin_status", lambda: sc.request(b"\x03\x00"))
        sc.request(b"\x03\x04" + b"benchpin")
        bench_fn("pin_lock", lambda: sc.request(b"\x03\x02"))
        sc.request(b"\x03\x01" + b"benchpin")
        bench_fn("pin_unlock", lambda: sc.request(b"\x03\x01" + b"benchpin"))
        secret = b"benchmark secret data 12345"
        sc.request(b"\x05\x01" + secret)
        bench_fn("storage_put", lambda: sc.request(b"\x05\x01" + secret))
        bench_fn("storage_get", lambda: sc.request(b"\x05\x00"))
        sc.close()
        bench_fn("sc_close", lambda: card.request(b"\xB0\xB7\x00\x00"))

    elif applet_name == "singleusekey":
        card.request(bytes([0x00, 0xA0, 0x00, 0x00]))
        bench("generate_key", bytes([0x00, 0xA0, 0x00, 0x00]))
        bench("get_pubkey", bytes([0x00, 0xA0, 0x01, 0x00]))
        msg_hash = hashlib.sha256(b"benchmark msg").digest()
        bench("sign_once", bytes([0x00, 0xA0, 0x02, 0x00]) + encode(msg_hash))
        pub1 = card.request(bytes([0x00, 0xA0, 0x01, 0x00]))
        card.request(bytes([0x00, 0xA0, 0x02, 0x00]) + encode(msg_hash))
        pub2 = card.request(bytes([0x00, 0xA0, 0x01, 0x00]))
        if pub1 != pub2:
            results.append({
                "applet": applet_name,
                "operation": "verify_rotation",
                "success": True,
                "duration_ms": 0,
                "response_len": 0,
                "notes": "pubkey changed after sign",
            })

    elif applet_name == "blindoracle":
        def do_sc_open():
            sc = SecureChannel(card)
            sc.open()
            return b"ok"
        bench_fn("sc_open", do_sc_open)

        sc = SecureChannel(card)
        sc.open()

        bench_fn("root_set_seed", lambda: sc.request(b"\x10\x00" + SEED))

        bench_fn("get_root_xpub", lambda: sc.request(b"\x11\x00"))

        bench_fn("derive_path", lambda: sc.request(b"\x11\x01" + b"\x00" + PATH_FULL))

        bench_fn("get_current_xpub", lambda: sc.request(b"\x11\x02"))

        msg = b"5" * 32
        bench_fn("sign_root", lambda: sc.request(b"\x11\x03" + msg + b"\x00"))

        bench_fn("sign_child", lambda: sc.request(b"\x11\x03" + msg + b"\x01"))

        bench_fn("derive_and_sign", lambda: sc.request(b"\x11\x04" + msg + b"\x01" + PATH_FULL))

        sc.close()
        bench_fn("sc_close", lambda: card.request(b"\xB0\xB7\x00\x00"))

    return results


def main():
    parser = argparse.ArgumentParser(description="Benchmark all applets on a real card")
    parser.add_argument("--gp-jar", default=os.path.join(os.path.dirname(__file__), "..", "..", "gp.jar"))
    parser.add_argument("--cap-dir", default=os.path.join(os.path.dirname(__file__), "..", "..", "build", "cap"))
    parser.add_argument("--reader", type=int, default=0)
    parser.add_argument("--gp-key", default="404142434445464748494A4B4C4D4E4F")
    parser.add_argument("--gp-key-ver", type=int, default=1)
    parser.add_argument("--iterations", type=int, default=5)
    parser.add_argument("--warmup", type=int, default=2)
    parser.add_argument("--output", default=None)
    parser.add_argument("--applet", default=None,
                        choices=list(APPLETS.keys()))
    parser.add_argument("--skip-flash", action="store_true")
    args = parser.parse_args()

    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=os.path.join(os.path.dirname(__file__), "..", ".."),
            stderr=subprocess.DEVNULL).decode().strip()[:12]
    except Exception:
        commit = "unknown"
    try:
        branch = subprocess.check_output(
            ["git", "branch", "--show-current"],
            cwd=os.path.join(os.path.dirname(__file__), "..", ".."),
            stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        branch = "unknown"

    reader_obj = get_reader()
    reader_name = str(reader_obj)
    atr = ""
    protocol = "T=1"

    applets_to_run = [args.applet] if args.applet else list(APPLETS.keys())
    all_results = []

    for applet_name in applets_to_run:
        info = APPLETS[applet_name]
        print(f"\n{'='*60}")
        print(f"  Applet: {applet_name} ({info['aid']})")
        print(f"{'='*60}")

        if not args.skip_flash:
            cap_path = os.path.join(args.cap_dir, info["cap"])
            if not os.path.exists(cap_path):
                print(f"  SKIP: {cap_path} not found. Run 'ant all' first.")
                continue
            ok = flash_applet(
                args.gp_jar, cap_path, info["aid"],
                info["package_aid"], args.gp_key, args.gp_key_ver,
            )
            if not ok:
                print(f"  SKIP: flash failed for {applet_name}")
                continue

        try:
            card = Card(info["aid"])
            atr = bytes(card.conn.getATR()).hex() if hasattr(card.conn, 'getATR') else atr
        except Exception as e:
            print(f"  SKIP: cannot connect: {e}")
            continue

        try:
            bench_results = run_benchmark(applet_name, card, args)
            all_results.extend(bench_results)
        except Exception as e:
            print(f"  ERROR: {e}")
        finally:
            try:
                card.disconnect()
            except Exception:
                pass

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_path = args.output or os.path.join(
        os.path.dirname(__file__), "..", "..", "artifacts", "benchmarks",
        f"{ts}-card.json",
    )
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "repo_commit": commit,
        "branch": branch,
        "card_name": "J3R180",
        "atr": atr,
        "reader": reader_name,
        "protocol": protocol,
        "test_mode": "card",
        "results": all_results,
    }

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nBenchmark written to {output_path}")

    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    print(f"{'Applet':<16} {'Operation':<24} {'Avg ms':>8} {'Min ms':>8} {'Max ms':>8} {'OK':>4}")
    print("-" * 74)
    for r in all_results:
        avg = f"{r['duration_ms']:.1f}" if r.get("duration_ms") is not None else "N/A"
        mn = f"{r.get('duration_min_ms', 0):.1f}" if r.get("duration_min_ms") is not None else "-"
        mx = f"{r.get('duration_max_ms', 0):.1f}" if r.get("duration_max_ms") is not None else "-"
        ok = "Y" if r["success"] else "N"
        print(f"{r['applet']:<16} {r['operation']:<24} {avg:>8} {mn:>8} {mx:>8} {ok:>4}")


if __name__ == "__main__":
    main()
