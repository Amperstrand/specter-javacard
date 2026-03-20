#!/usr/bin/env python3
"""
Card key failure blacklist.

Prevents repeated authentication attempts with wrong keys against a card,
which can permanently lock the card (e.g., after too many failed SCP attempts).

Card identification priority:
  1. CPLC IC serial number (GET DATA 00CA9F7F) - unique per chip
  2. Fallback: ATR + reader name (less specific but better than nothing)

Usage:
    from util.card_key_guard import CardKeyGuard

    guard = CardKeyGuard()
    guard.check_key("404142434445464748494A4B4C4D4E4F")
    # ... if auth fails:
    guard.record_failure("404142434445464748494A4B4C4D4E4F")
"""

import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from smartcard.System import readers
from smartcard.CardConnection import CardConnection

CONFIG_DIR = Path.home() / ".specter-javacard"
FAILURE_DB = CONFIG_DIR / "key_failures.json"


def _get_card_identity_raw():
    """Try to get a unique card identity. Returns (identifier_string, method)."""
    try:
        rarr = readers()
        if len(rarr) == 0:
            return None, None
        reader = rarr[0]
        conn = reader.createConnection()
        conn.connect(CardConnection.T1_protocol)
        try:
            data, *sw = conn.transmit([0x00, 0xCA, 0x9F, 0x7F, 0x00])
            if bytes(sw) == b"\x90\x00" and len(data) >= 10:
                ic_serial = bytes(data[5:10]).hex()
                if ic_serial != "0000000000":
                    return ic_serial, "cplc"
                cplc_full = bytes(data).hex()
                return cplc_full, "cplc-full"
        except Exception:
            pass
        finally:
            try:
                conn.disconnect()
            except Exception:
                pass
    except Exception:
        pass

    try:
        rarr = readers()
        if len(rarr) == 0:
            return None, None
        reader = rarr[0]
        conn = reader.createConnection()
        conn.connect(CardConnection.T1_protocol)
        try:
            atr = bytes(conn.getATR()).hex()
            reader_name = str(reader)
            return f"{atr}|{reader_name}", "atr+reader"
        except Exception:
            pass
        finally:
            try:
                conn.disconnect()
            except Exception:
                pass
    except Exception:
        pass

    return None, None


def _card_id_hash(identifier):
    return hashlib.sha256(identifier.encode()).hexdigest()[:16]


def _key_hash(key_hex):
    return hashlib.sha256(key_hex.encode()).hexdigest()[:16]


class CardKeyGuard:
    def __init__(self, force=False):
        self.force = force
        self._card_id = None
        self._card_method = None
        self._db = self._load_db()

    @property
    def card_id(self):
        if self._card_id is None:
            raw_id, method = _get_card_identity_raw()
            if raw_id is None:
                raise RuntimeError("Cannot identify card - no reader or card detected")
            self._card_id = _card_id_hash(raw_id)
            self._card_method = method
        return self._card_id

    @property
    def card_method(self):
        _ = self.card_id
        return self._card_method

    def _load_db(self):
        if FAILURE_DB.exists():
            try:
                with open(FAILURE_DB) as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    def _save_db(self):
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(FAILURE_DB, "w") as f:
            json.dump(self._db, f, indent=2)

    def check_key(self, key_hex):
        """Check if this key has been blacklisted for the current card.

        Raises RuntimeError if the key is blacklisted and force=False.
        Returns True if key is OK, False if blacklisted (when force=True).
        """
        if self.force:
            return True

        cid = self.card_id
        kh = _key_hash(key_hex)

        if cid in self._db and kh in self._db[cid]:
            ts = self._db[cid][kh]
            method = self.card_method
            raise RuntimeError(
                f"Key {_key_hash(key_hex)} has been tried and FAILED on this card "
                f"(identified via {method}, id={cid}) at {ts}.\n"
                f"This prevents accidental card lockout from repeated wrong key attempts.\n"
                f"If you are sure this key is correct, re-run with --force-key."
            )
        return True

    def record_failure(self, key_hex):
        """Record that this key failed authentication for the current card."""
        cid = self.card_id
        kh = _key_hash(key_hex)
        ts = datetime.now(timezone.utc).isoformat()

        if cid not in self._db:
            self._db[cid] = {}
        self._db[cid][kh] = ts
        self._save_db()

        method = self.card_method
        print(
            f"[card_key_guard] Recorded failed key attempt: "
            f"card={cid} (via {method}), key={kh}, time={ts}",
            file=sys.stderr,
        )

    def list_failures(self):
        """List all recorded failures."""
        cid = self.card_id
        if cid not in self._db or not self._db[cid]:
            print(f"No failed key attempts recorded for card {cid}.", file=sys.stderr)
            return
        print(f"Failed key attempts for card {cid} (via {self.card_method}):", file=sys.stderr)
        for kh, ts in self._db[cid].items():
            print(f"  key={kh}  failed_at={ts}", file=sys.stderr)

    def clear_failures(self):
        """Clear all recorded failures for the current card."""
        cid = self.card_id
        if cid in self._db:
            del self._db[cid]
            self._save_db()
            print(f"Cleared all failed key attempts for card {cid}.", file=sys.stderr)


def get_card_serial():
    """Return a human-readable card identifier string, or None."""
    raw_id, method = _get_card_identity_raw()
    if raw_id is None:
        return None
    return f"{raw_id} (via {method})"
