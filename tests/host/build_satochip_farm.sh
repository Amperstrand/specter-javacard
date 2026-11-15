#!/usr/bin/env bash
# Build the SatoChip version farm: compile Toporin SatochipApplet release
# tags into jcardsim-servable classdirs (the vpcd version farm, 2026-11-15).
#
# Each tag becomes build/classes/Satochip-<tag>/ — serve one per vicc.py
# instance + reader stanza:
#
#   # member config (per tag): /etc/reader.conf.d stanza with its OWN .so
#   # copy (ifd-vpcd's ctx[] is library-global and pcscd caches dlopen by
#   # LIBPATH — two stanzas sharing one .so clobber each other; the
#   # per-stanza-copy rule comes from ccid-eofeject's vjavacard setup) and
#   # a NON-OVERLAPPING port range (VPCDSLOTS=2: one stanza binds port AND
#   # port+1):
#     FRIENDLYNAME "jCardSim VPCD v016"
#     DEVICENAME /dev/null:0x8C87        # 35975 (+1 = slot 00 01)
#     LIBPATH .../libifdvpcd-jcardsim-v016.so   # cp of -jcardsim.so
#     CHANNELID 0x8C87
#
#   tmux new-session -d -s jcardsim-vpcd-sato16 \
#     'cd tests/tests/util && python3 vicc.py --vpcd-port 35975 \
#      --sim-port 6668 --aid 5361746F43686970 \
#      --applet org.satochip.applet.Satochip --classdir Satochip-v0.16-0.1'
#
# Personalize each member (zero-value test seed) with
# specter-diy-m2/satochip-sim-setup.py, then run the battery across the
# farm: CARDMAN_BATTERY_READER="jCardSim VPCD v016 00 00" \
# python3 cardman-battery.py  (25/25 verified on both v0.14-0.2 and
# v0.16-0.1, 2026-11-15).
#
# Compile note: the applets need a JC 2.2.2+ classic API (ALG_SHA_256,
# APDU.getOffsetCdata) — jc221_kit is too old; jc304 api_classic.jar works
# for both tags. Execution happens on the jcardsim bundled in simulator.jar
# regardless of the compile-time API jar.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
API_JAR="$ROOT/sdks/jc304_kit/lib/api_classic.jar"
OUT_BASE="$ROOT/build/classes"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# tag|src-prefix|applet-class
MEMBERS=(
  "v0.14-0.2|src/org/satochip/applet|org.satochip.applet.CardEdge"
  "v0.16-0.1|src/main/java/org/satochip/applet|org.satochip.applet.Satochip"
)

for m in "${MEMBERS[@]}"; do
  IFS='|' read -r tag prefix applet <<< "$m"
  echo "=== Satochip-$tag ($applet) ==="
  src="$WORK/$tag/$prefix"
  mkdir -p "$src"
  base_url="https://raw.githubusercontent.com/Toporin/SatochipApplet/$tag/$prefix"
  case "$tag" in
    v0.14-0.2) files="Biginteger Bip32ObjectManager CardEdge HmacSha160 HmacSha512 Secp256k1 Transaction" ;;
    v0.16-0.1) files="Biginteger HmacSha160 HmacSha512 Satochip Secp256k1 SecureChannel SharedMemory" ;;
  esac
  for f in $files; do
    curl -sL "$base_url/$f.java" -o "$src/$f.java"
    grep -q "class\|interface" "$src/$f.java" || { echo "fetch failed: $f" >&2; exit 1; }
  done
  out="$OUT_BASE/Satochip-$tag"
  rm -rf "$out" && mkdir -p "$out"
  javac --release 8 -nowarn -cp "$API_JAR" -d "$out" "$src"/*.java
  echo "built: $out (applet $applet, $(find "$out" -name '*.class' | wc -l) classes)"
done
echo "farm build complete"
