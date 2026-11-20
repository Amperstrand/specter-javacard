#!/usr/bin/env bash
# Build + deploy libifdvpcd-jcardsim.so — the jCardSim vpcd tier's reader
# driver (L2 bridge, 2026-11-15).
#
# Base: upstream vsmartcard @ 93286a90 + the Amperstrand #326 patch (EOF
# eject + SO_RCVTIMEO; copied from
# ccid-eofeject/tests/hardware/host/libifdvpcd-amperstrand.patch — that
# repo owns the driver lineage) + jcardsim-pthread-lock.patch (ours).
#
# WHY THE PTHREAD PATCH IS LOAD-BEARING (bench-proven 2026-11-15):
# upstream lock.c's pthread branch has NEVER compiled — `r` undeclared,
# PTHREAD_MUTEX_INITIALIZER used as an assignment — so every build that
# does not pass -DHAVE_PTHREAD (which is every build, including the
# eofeject one: its gcc line has no -DHAVE_PTHREAD) silently compiles
# the NO-OP lock stub. pcscd's presence poller (IFDHICCPresence -> 0x04
# ATR exchange) then races SCardTransmit on the same socket and frames
# cross-associate: transmits return ATR bytes as R-APDUs (the SW=1084
# class), cascading into "Card was removed". Reproduced deterministically
# at ~13 APDUs/s; with the mutex driver: 0 desyncs in 60+ exchanges.
# The upstream fix is worth an owner-gated upstream draft (manual-only
# per the external-posting CHANNEL rule).
#
# Usage:
#   ./build_libifdvpcd_jcardsim.sh build     # -> libifdvpcd-jcardsim.so here
#   ./build_libifdvpcd_jcardsim.sh deploy    # -> /usr/local/lib/pcsc/drivers/serial/
#   ./build_libifdvpcd_jcardsim.sh setup     # -> write /etc/reader.conf.d/vpcd-jcardsim
#
# After deploy+setup: restart pcscd under the bench flock:
#   flock /run/lock/bench-pcscd.lock sudo systemctl restart pcscd
set -euo pipefail

UPSTREAM_PIN=93286a90d2411120ae17299f9902e1fdd8954185
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/upstream-vsc"
OUT="$HERE/libifdvpcd-jcardsim.so"
DEST_DIR="/usr/local/lib/pcsc/drivers/serial"
DEST="$DEST_DIR/libifdvpcd-jcardsim.so"
READER_CONF="/etc/reader.conf.d/vpcd-jcardsim"
PORT_HEX="0x8C85"   # 35973 — slot 00 00 (slot 00 01 = 35974)

cmd="${1:-}"
case "$cmd" in
  build)
    rm -rf "$SRC"
    git clone --quiet https://github.com/frankmorgner/vsmartcard.git "$SRC"
    git -C "$SRC" checkout --quiet "$UPSTREAM_PIN"
    git -C "$SRC" apply "$HERE/patches/amperstrand-326.patch"
    git -C "$SRC" apply "$HERE/patches/jcardsim-pthread-lock.patch"
    # HAVE_ARPA_INET_H is an autoconf macro; ifd-vpcd.c gates <arpa/inet.h>
    # on it. Without it gcc>=14 fails the build (implicit htonl declaration).
    gcc -O2 -fPIC -shared \
      -DHAVE_DECL_MSG_NOSIGNAL=1 -DHAVE_DECL_SO_NOSIGPIPE=0 \
      -DHAVE_ARPA_INET_H=1 \
      -DHAVE_PTHREAD=1 \
      -DPACKAGE_VERSION='"3.3+jcardsim1"' -DVPCDSLOTS=2 \
      -o "$OUT" \
      "$SRC/virtualsmartcard/src/vpcd/vpcd.c" \
      "$SRC/virtualsmartcard/src/vpcd/lock.c" \
      "$SRC/virtualsmartcard/src/ifd-vpcd/ifd-vpcd.c" \
      -I/usr/include/PCSC \
      -I"$SRC/virtualsmartcard/src/vpcd" \
      -I"$SRC/virtualsmartcard/src/ifd-vpcd" \
      -lpthread
    nm -D "$OUT" | grep -q pthread_mutex_lock \
      || { echo "FATAL: mutex symbols missing — lock compiled as stub" >&2; exit 1; }
    rm -rf "$SRC"
    echo "built: $OUT (upstream $UPSTREAM_PIN + amperstrand-326 + pthread-lock)"
    ;;
  deploy)
    [ -f "$OUT" ] || { echo "run 'build' first" >&2; exit 1; }
    install -m 644 "$OUT" "$DEST"
    echo "deployed: $DEST"
    ;;
  setup)
    sudo -n tee "$READER_CONF" >/dev/null <<EOF
FRIENDLYNAME "jCardSim VPCD"
DEVICENAME /dev/null:${PORT_HEX}
LIBPATH ${DEST}
CHANNELID ${PORT_HEX}
EOF
    echo "wrote $READER_CONF (port $PORT_HEX = slot 00 00; +1 = slot 00 01)"
    ;;
  *)
    echo "usage: $0 {build|deploy|setup}" >&2
    exit 2
    ;;
esac
