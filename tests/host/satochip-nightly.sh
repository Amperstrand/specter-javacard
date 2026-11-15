#!/usr/bin/env bash
# satochip-nightly — the contract sync loop, monitor-only + farm self-heal.
#
# Runs (in order):
#   0. ensure-farm: the three vicc adapters up (tmux), SatoChip members
#      personalized (deterministic zero-value seed) — restart/repersonalize
#      when missing. This is the ONLY mutating phase; everything else reads.
#   1. spec-vs-tag: extract_apdu_spec.py — fails on any drift between
#      satochip-protocol.yaml and the pinned Toporin tags.
#   2. tag watch: unknown upstream tags land in the report as WARN
#      (never auto-added — a new tag is a review event).
#   3. golden vectors: record-farm-vectors.py --check.
#   4. rust conformance: cargo run --bin conformance on both members.
#
# Report: /tmp/opencode/satochip-sync/report-<date>.txt (+ latest symlink);
# exit non-zero on any failure. Deployed as systemd user timer
# satochip-sync.timer (see systemd/ next to this script).
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
HOST_DIR="$HERE"
M2_DIR="${SPECTER_M2_DIR:-/home/ubuntu/src/specter-diy-m2}"
CRATE="$HOST_DIR/satochip-client"
VICC="$HOST_DIR/../tests/util/vicc.py"
OUT_DIR="/tmp/opencode/satochip-sync"
REPORT="$OUT_DIR/report-$(date +%Y%m%d-%H%M%S).txt"
FAIL=0

mkdir -p "$OUT_DIR"
exec > >(tee -a "$REPORT") 2>&1
echo "== satochip sync $(date -Is) =="

note_fail() { echo "FAIL: $*"; FAIL=1; }

ensure_adapter() { # name vpcd_port sim_port aid applet classdir
    local name=$1 port=$2 sim=$3 aid=$4 applet=$5 classdir=$6
    if tmux has-session -t "$name" 2>/dev/null \
       && pgrep -f "vicc.py --vpcd-port $port" >/dev/null; then
        echo "adapter $name: up"
        return 0
    fi
    echo "adapter $name: (re)starting"
    tmux kill-session -t "$name" 2>/dev/null
    pkill -f "simulator.jar -p $sim" 2>/dev/null
    sleep 1
    tmux new-session -d -s "$name" \
        "cd '$(dirname "$VICC")' && python3 '$VICC' --vpcd-port $port \
         --sim-port $sim --aid $aid --applet $applet --classdir $classdir \
         > /tmp/opencode/jcardsim-vpcd/$name.log 2>&1"
    sleep 4
    pgrep -f "vicc.py --vpcd-port $port" >/dev/null \
        || { note_fail "adapter $name did not start"; return 1; }
}

ensure_personalized() { # reader_substr (uses CARDMAN_BATTERY_READER)
    local reader=$1
    (cd "$M2_DIR" && CARDMAN_BATTERY_READER="$reader" timeout 120 \
        python3 - <<'PY' 2>/dev/null
import importlib.util, os
spec = importlib.util.spec_from_file_location(
    "cmb", os.path.join(os.getcwd(), "cardman-battery.py"))
cmb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cmb)
from keystore.javacard.applets.satochip_applet import SatochipApplet
conn = cmb.PyscardConnection()
applet = SatochipApplet(conn)
applet.select()
_, s1, s2 = applet.get_card_status()
print("SEEDED" if (s1, s2) == (0x90, 0x00) else "UNKNOWN")
PY
    ) | tail -1
}

ensure_farm() {
    ensure_adapter jcardsim-vpcd 35973 6666 B00B5111FF01 toys.SecureApplet Secure \
        || note_fail "specter SecureApplet adapter down"
    ensure_adapter jcardsim-vpcd-sato 35974 6667 5361746F43686970 \
        org.satochip.applet.CardEdge Satochip-v0.14-0.2 \
        || note_fail "satochip v0.14 adapter down"
    ensure_adapter jcardsim-vpcd-sato16 35975 6668 5361746F43686970 \
        org.satochip.applet.Satochip Satochip-v0.16-0.1 \
        || note_fail "satochip v0.16 adapter down"
    for reader in "jCardSim VPCD 00 01" "jCardSim VPCD v016 00 00"; do
        state=$(ensure_personalized "$reader")
        if [ "$state" != "SEEDED" ]; then
            echo "member $reader not personalized — re-personalizing"
            (cd "$M2_DIR" && CARDMAN_BATTERY_READER="$reader" timeout 120 \
                python3 satochip-sim-setup.py >/dev/null 2>&1) \
                || note_fail "re-personalization failed for $reader"
        fi
    done
}

phase_spec() {
    echo "-- spec-vs-tag"
    "$HOST_DIR/extract_apdu_spec.py" || note_fail "spec drift vs pinned tags"
    echo "-- upstream tag watch"
    python3 - "$HOST_DIR/spec/satochip-protocol.yaml" <<'PY'
import json, re, sys, urllib.request
spec_versions = list(__import__("yaml").safe_load(open(sys.argv[1]))["versions"])

def vkey(tag):
    m = re.match(r"v?(\d+)\.(\d+)", tag)
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)

newest_known = max(vkey(v) for v in spec_versions)
with urllib.request.urlopen(
        "https://api.github.com/repos/Toporin/SatochipApplet/tags?per_page=30",
        timeout=30) as r:
    for tag in json.load(r):
        name = tag["name"]
        if vkey(name) > newest_known:
            print("WARN: upstream tag %s newer than spec's %s (review event)"
                  % (name, newest_known))
PY
}

phase_vectors() {
    echo "-- golden vectors"
    (cd "$M2_DIR" && timeout 240 python3 record-farm-vectors.py --check \
        >/dev/null 2>&1) || note_fail "golden-vector drift"
}

phase_rust() {
    echo "-- rust conformance"
    (cd "$CRATE" && timeout 300 cargo run --quiet --bin conformance -- \
        --reader "jCardSim VPCD 00 01" --count 10 >/dev/null 2>&1) \
        || note_fail "rust conformance v0.14 member"
    (cd "$CRATE" && timeout 300 cargo run --quiet --bin conformance -- \
        --reader "jCardSim VPCD v016 00 00" --count 10 >/dev/null 2>&1) \
        || note_fail "rust conformance v0.16 member"
}

ensure_farm
phase_spec
phase_vectors
phase_rust

ln -sfn "$REPORT" "$OUT_DIR/latest.txt"
if [ "$FAIL" -eq 0 ]; then
    echo "== satochip sync OK =="
else
    echo "== satochip sync FAILURES PRESENT =="
fi
exit $FAIL
