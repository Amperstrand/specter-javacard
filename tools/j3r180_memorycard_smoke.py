#!/usr/bin/env python3
import os
import sys
from binascii import unhexlify


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UTILS_DIR = os.path.join(ROOT, "tests", "tests")
sys.path.insert(0, UTILS_DIR)

from util.card import Card, ISOException  # noqa: E402
from util.securechannel import SecureChannel, SecureError  # noqa: E402


AID = "B00B5111CB01"


def env_bytes(name: str, default: bytes) -> bytes:
    v = os.environ.get(name)
    if v is None:
        return default
    v = v.strip()
    if v.startswith("0x"):
        v = v[2:]
    # Accept hex if it looks like hex, otherwise treat as utf-8.
    if all(c in "0123456789abcdefABCDEF" for c in v) and len(v) % 2 == 0:
        return unhexlify(v)
    return v.encode("utf-8")


def main() -> int:
    pin = env_bytes("SMOKE_PIN", b"My PIN code")
    secret = env_bytes("SMOKE_SECRET", b"j3r180 smoke secret")

    try:
        card = Card(AID)
        card.connect()

        sc = SecureChannel(card)
        sc.open()  # defaults to ES mode (B0 B4) as used by specter-diy

        # 1. secure echo
        got = sc.request(b"\x00\x00ping")
        assert got == b"ping"

        # 2. PIN status
        status = sc.request(b"\x03\x00")
        left, total, is_set = list(status)

        # 3. set PIN if needed
        if is_set == 0:
            sc.request(b"\x03\x04" + pin)
        # 4. unlock if locked
        elif is_set == 1:
            sc.request(b"\x03\x01" + pin)

        # 5. write secret
        stored = sc.request(b"\x05\x01" + secret)
        assert stored == secret

        # 6. read secret
        read_back = sc.request(b"\x05\x00")
        assert read_back == secret

        # 7. lock + close channel
        sc.request(b"\x03\x02")
        sc.close()

        print("PASS: MemoryCard J3R180 ES flow succeeded")
        print(f"  PIN_set={is_set} attempts_left={left}/{total}")
        return 0

    except SecureError as e:
        print(f"FAIL: SecureChannel error SW=0x{e.code:04x}: {e}")
        return 2
    except ISOException as e:
        print(f"FAIL: ISOException SW=0x{e.code:04x}")
        return 3
    except Exception as e:
        print(f"FAIL: unexpected error: {e.__class__.__name__}: {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

