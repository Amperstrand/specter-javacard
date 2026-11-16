#!/usr/bin/env python3
"""vicc — serve a jCardSim applet to pcscd through a vpcd slot (L2 tier).

The bridge the M2 matrix was missing: pcscd -> libifdvpcd-amperstrand.so
(vpcd listener) -> THIS adapter -> jcsimcli (simulator.jar) -> real applet
classes. The host client stack then talks to the simulator through the
SAME pcscd API it uses for the real CardMan reader.

vpcd wire facts (bench-proven references, ccid-eofeject #261 tiers a/b:
tests/hardware/nfc/vpicc_table.py, host/vjavacard VpcdBridge.java):
  - frame = 2-byte big-endian length + payload
  - 1-byte controls: ONLY Get ATR (0x04) is answered, with the ATR bytes.
    OFF (0x00) / ON (0x01) / RESET (0x02) are one-way announcements —
    answering RESET queues an extra ATR that desyncs the next transmit's
    status word (the SW=1084 class, bolty-rs #226), and a 0-length frame
    means "ICC absent" and ejects the slot. Silence must be TRUE silence.
  - len > 1 = C-APDU -> exactly one R-APDU frame back
  - we are the TCP CLIENT (vpcd listens); reconnect ~0.5 s on error; an
    idle socket is NOT an error (post-pcscd-restart transmit-dead-window
    mitigation — a real card stays silent while attached, so do we)
  - the slot is single-client: never run two adapters against one port

jcsimcli side: raw lock-step APDU stream on its TCP port (no framing —
see util/simulator.py: sendall(capdu), recv(rapdu)). We drain until the
socket goes quiet so multi-segment responses reassemble.

Card-state note: the applet instance lives in the JVM for the adapter's
lifetime; a pcscd power cycle does NOT reset it (jcardsim 2.2.2's reset()
leaves the runtime unusable — bench-verified 2026-10-22 in the vjavacard
lane). Clients re-SELECT after (re)connect, which is all the ISO model
guarantees anyway. Kill the adapter for a factory-fresh applet.
"""
import argparse
import os
import queue as _queue
import signal
import socket
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
JAVACARD_ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
SIM_JAR = os.path.join(JAVACARD_ROOT, "simulator.jar")
CLASSES_ROOT = os.path.join(JAVACARD_ROOT, "build", "classes")

# T=1 J3R180 shape — the ATR proven against libifdvpcd-amperstrand.so +
# pcscd in the eofeject vjavacard lane (clients connect T=1, matching
# util/card.py's default).
DEFAULT_ATR_HEX = "3B858131FE458073C8211084"

VICC_OFF = 0x00
VICC_ON = 0x01
VICC_RESET = 0x02
VICC_ATR = 0x04

DEBUG = bool(os.environ.get("VICC_DEBUG"))


def log(msg):
    print("%s vicc: %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


class JCardSim:
    """Owns the jcsimcli JVM process and its raw APDU socket."""

    def __init__(self, aid, applet, classdir, port, atr_hex, host="127.0.0.1"):
        self.aid = aid
        self.applet = applet
        self.classdir = classdir
        self.host = host
        self.port = port
        self.atr_bytes = bytes.fromhex(atr_hex)
        self.proc = None
        self.sock = None

    def start(self, timeout=30):
        """Launch the JVM (fresh applet state) and connect to its port."""
        self.stop()
        url = "file://%s/%s/" % (CLASSES_ROOT, self.classdir)
        args = ["java", "-jar", SIM_JAR,
                "-p", str(self.port),
                "-a", self.aid,
                "-c", self.applet,
                "-u", url]
        log("starting jcsimcli: %s (classes %s)" % (" ".join(args[2:5]), url))
        self.proc = subprocess.Popen(args, start_new_session=True)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                self.sock = socket.create_connection((self.host, self.port),
                                                      timeout=2)
                self.sock.settimeout(1.0)
                return
            except OSError:
                if self.proc.poll() is not None:
                    raise RuntimeError("jcsimcli died rc=%s" % self.proc.returncode)
                time.sleep(0.2)
        raise RuntimeError("jcsimcli never listened on %s:%s" %
                           (self.host, self.port))

    def stop(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
        if self.proc is not None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    self.proc.kill()
                except OSError:
                    pass
            self.proc = None

    def apdu(self, capdu):
        """One lock-step exchange on the raw stream; drains until quiet."""
        if self.sock is None:
            raise ConnectionError("jcsimcli not connected")
        if DEBUG:
            log(">> %s" % capdu.hex())
        self.sock.sendall(capdu)
        buf = b""
        self.sock.settimeout(2.0)  # JVM first segment (GC pauses covered)
        while True:
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                raise ConnectionError("jcsimcli closed the socket")
            buf += chunk
            self.sock.settimeout(0.05)  # inter-segment drain
        if len(buf) < 2:
            raise ConnectionError("jcsimcli returned %d bytes" % len(buf))
        if DEBUG:
            log("<< %s" % buf.hex())
        return buf


def send_frame(sock, payload):
    sock.sendall(len(payload).to_bytes(2, "big") + payload)


class VpcdSession:
    """One vpcd session, event-driven (two threads):

    - reader thread: parses frames; Get ATR (0x04) is answered INSTANTLY
      on this thread — the driver's presence poll must never wait behind
      a JVM round trip (a >2 s stall trips the driver's SO_RCVTIMEO, and
      the late ATR lands on a transmit boundary = the SW=1084 desync
      class; bench-observed 2026-11-15 with the naive single-threaded
      loop). C-APDUs are queued for the worker.
    - worker: serializes APDUs through jcsimcli (the JVM link is a
      lock-step raw stream — never concurrent) and sends R-APDUs.

    Ordering guarantee: the driver holds its io_lock across each
    request/response pair (vpcd.c vicc_transmit), so at most ONE driver
    request is ever outstanding; controls can only arrive between our
    responses, never inside one — frame-type dispatch is therefore
    association-safe.
    """

    def __init__(self, sock, sim, ordered_controls=False, apdu_delay_ms=0):
        self.sock = sock
        self.sim = sim
        self.ordered_controls = ordered_controls
        self.apdu_delay_ms = apdu_delay_ms
        self.send_lock = threading.Lock()
        self.apdus = _queue.Queue()
        self.dead = threading.Event()

    def send(self, payload):
        with self.send_lock:
            self.sock.sendall(len(payload).to_bytes(2, "big") + payload)

    def reader_loop(self):
        sock = self.sock
        sock.settimeout(5.0)
        buf = b""
        while not self.dead.is_set():
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                continue  # idle != dead (transmit-dead-window mitigation)
            except OSError as e:
                # RST/EBADF & friends = session over (a pcscd restart with
                # unread data in the kernel buffer RSTs instead of FINning;
                # without this the reader thread dies, `dead` is never set
                # and the worker loops forever as a zombie — bench-proven
                # 2026-11-15 when two adapters failed to re-attach)
                log("vpcd session reset (%s)" % e)
                self.dead.set()
                return
            if not chunk:
                log("vpcd driver closed the session")
                self.dead.set()
                return
            buf += chunk
            while len(buf) >= 2:
                n = int.from_bytes(buf[:2], "big")
                if len(buf) < 2 + n:
                    break
                msg, buf = buf[2:2 + n], buf[2 + n:]
                if len(msg) == 1:
                    if msg[0] == VICC_ATR and not self.ordered_controls:
                        self.send(self.sim.atr_bytes)  # instant, no JVM hop
                    elif msg[0] == VICC_ATR:
                        # ordered mode: the ATR answer queues behind any
                        # in-flight JVM APDU reply — request-order replies
                        # (v1 semantics). Reproduces the driver-side
                        # thread-steal race window deterministically:
                        # both answers land together, and the unlocked
                        # driver's presence thread can read the R-APDU
                        # the transmit thread was waiting for.
                        self.apdus.put(("control", VICC_ATR))
                    # OFF/ON/RESET: true silence (see module docstring)
                    continue
                self.apdus.put(msg)

    def worker_loop(self):
        while not self.dead.is_set():
            try:
                msg = self.apdus.get(timeout=0.5)
            except _queue.Empty:
                continue
            if isinstance(msg, tuple) and msg[0] == "control":
                try:
                    self.send(self.sim.atr_bytes)
                except OSError:
                    self.dead.set()
                continue
            if self.apdu_delay_ms > 0:
                time.sleep(self.apdu_delay_ms / 1000.0)
            try:
                self.send(self.sim.apdu(msg))
            except (ConnectionError, OSError) as e:
                log("jcsimcli link lost (%s) — restarting JVM" % e)
                try:
                    self.sim.start()
                    self.send(self.sim.apdu(msg))
                except (RuntimeError, ConnectionError, OSError) as e2:
                    log("restart failed (%s) — answering 6F00" % e2)
                    try:
                        self.send(b"\x6f\x00")
                    except OSError:
                        self.dead.set()


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--vpcd-host", default="127.0.0.1")
    ap.add_argument("--vpcd-port", type=int, default=35973)
    ap.add_argument("--sim-port", type=int, default=6666)
    ap.add_argument("--aid", default="B00B5111FF01",
                    help="applet instance AID (hex, no separators)")
    ap.add_argument("--applet", default="toys.SecureApplet")
    ap.add_argument("--classdir", default="Secure",
                    help="dir under build/classes carrying the applet")
    ap.add_argument("--atr", default=DEFAULT_ATR_HEX)
    ap.add_argument("--ordered-controls", action="store_true",
                    help="answer ATR controls in request order (v1 semantics) — reproduces the unlocked-driver race")
    ap.add_argument("--apdu-delay-ms", type=int, default=0,
                    help="delay APDU replies by N ms (widens the driver-side race window for lock testing)")
    args = ap.parse_args(argv)

    sim = JCardSim(args.aid, args.applet, args.classdir, args.sim_port,
                   args.atr)
    sim.start()

    def _term(signum, frame):
        log("signal %d — shutting down" % signum)
        sim.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _term)
    signal.signal(signal.SIGINT, _term)

    log("serving vpcd %s:%d (ATR %s)" %
        (args.vpcd_host, args.vpcd_port, args.atr))
    while True:
        try:
            sock = socket.create_connection(
                (args.vpcd_host, args.vpcd_port), timeout=2)
        except OSError:
            time.sleep(0.5)
            continue
        session = None
        try:
            log("attached to vpcd slot")
            session = VpcdSession(sock, sim,
                               ordered_controls=args.ordered_controls,
                               apdu_delay_ms=args.apdu_delay_ms)
            reader = threading.Thread(target=session.reader_loop,
                                      daemon=True)
            reader.start()
            session.worker_loop()
        except OSError as e:
            log("vpcd session error: %s" % e)
        finally:
            if session is not None:
                session.dead.set()
            sock.close()
        time.sleep(0.2)


if __name__ == "__main__":
    sys.exit(main())
