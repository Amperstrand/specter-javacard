#!/usr/bin/env python3
import unittest, os, hashlib
from util.securechannel import SecureChannel, SecureError

AID = "B00B5111CB01"
APPLET = "toys.MemoryCardApplet"
CLASSDIR = "MemoryCard"

mode = os.environ.get('TEST_MODE', "simulator")
if mode=="simulator":
    from util.simulator import Simulator, ISOException
    sim = Simulator(AID, APPLET, CLASSDIR)
elif mode=="card":
    from util.card import Card, ISOException
    sim = Card(AID)
else:
    raise RuntimeError("Not supported")

def setUpModule():
    sim.connect()

def tearDownModule():
    sim.disconnect()

SELECT     = b"\x00\xA4\x04\x00"
GET_RANDOM = b"\xB0\xB1\x00\x00"
GET_PUBKEY = b"\xB0\xB2\x00\x00"

def encode(data):
    return bytes([len(data)])+data

def sha256_pin(pin_str):
    return hashlib.sha256(pin_str.encode()).digest()

PIN_UNSET = 0
PIN_LOCKED = 1
PIN_UNLOCKED = 2

CMD_STORAGE_GET = b"\x05\x00"
CMD_STORAGE_PUT = b"\x05\x01"
CMD_PIN_STATUS = b"\x03\x00"
CMD_PIN_UNLOCK = b"\x03\x01"
CMD_PIN_LOCK = b"\x03\x02"
CMD_PIN_CHANGE = b"\x03\x03"
CMD_PIN_SET = b"\x03\x04"
CMD_PIN_UNSET = b"\x03\x05"
CMD_ECHO = b"\x00\x00"
CMD_RAND = b"\x01\x00"


def get_pin_status(sc):
    status = sc.request(CMD_PIN_STATUS)
    return status[0], status[1], status[2]


def ensure_pin_unset(sc):
    status = get_pin_status(sc)
    left, total, is_set = status
    if is_set == PIN_UNSET:
        return
    if is_set == PIN_UNLOCKED:
        pin = b"\x00" * 32
        sc.request(CMD_PIN_UNSET + pin)
        return
    if is_set == PIN_LOCKED:
        raise RuntimeError("Card is locked with unknown PIN, cannot unset")


class SpecterDIYTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_secure_channel(self):
        sc = SecureChannel(sim)
        sc.open()
        self.assertTrue(sc.is_open)
        return sc

    def test_is_available(self):
        sim.request(SELECT + encode(bytes.fromhex(AID)))
        pub = sim.request(GET_PUBKEY)
        self.assertEqual(pub[0], 0x04)
        self.assertEqual(len(pub), 65)
        sc = SecureChannel(sim)
        sc.open()
        self.assertTrue(sc.is_open)
        sc.close()
        self.assertFalse(sc.is_open)

    def test_set_pin_hashed(self):
        sc = self.get_secure_channel()
        try:
            ensure_pin_unset(sc)
            left, total, is_set = get_pin_status(sc)
            self.assertEqual(is_set, PIN_UNSET)
            pin_hash = sha256_pin("1234")
            sc.request(CMD_PIN_SET + pin_hash)
            left, total, is_set = get_pin_status(sc)
            self.assertEqual(is_set, PIN_UNLOCKED)
        finally:
            sc.request(CMD_PIN_LOCK)
            pin_hash = sha256_pin("1234")
            sc.request(CMD_PIN_UNSET + pin_hash)
            sc.close()

    def test_unlock_hashed(self):
        sc = self.get_secure_channel()
        try:
            ensure_pin_unset(sc)
            pin_hash = sha256_pin("mypin")
            sc.request(CMD_PIN_SET + pin_hash)
            sc.request(CMD_PIN_LOCK)
            left, total, is_set = get_pin_status(sc)
            self.assertEqual(is_set, PIN_LOCKED)
            sc.request(CMD_PIN_UNLOCK + pin_hash)
            left, total, is_set = get_pin_status(sc)
            self.assertEqual(is_set, PIN_UNLOCKED)
        finally:
            sc.request(CMD_PIN_LOCK)
            sc.request(CMD_PIN_UNSET + sha256_pin("mypin"))
            sc.close()

    def test_wrong_pin_decrements_counter(self):
        sc = self.get_secure_channel()
        try:
            ensure_pin_unset(sc)
            pin_hash = sha256_pin("correct")
            sc.request(CMD_PIN_SET + pin_hash)
            sc.request(CMD_PIN_LOCK)
            left, total, is_set = get_pin_status(sc)
            self.assertEqual(is_set, PIN_LOCKED)
            wrong_hash = sha256_pin("wrong")
            with self.assertRaises(SecureError) as e:
                sc.request(CMD_PIN_UNLOCK + wrong_hash)
            left, total, is_set = get_pin_status(sc)
            self.assertEqual(left, total - 1)
            self.assertEqual(is_set, PIN_LOCKED)
            sc.request(CMD_PIN_UNLOCK + pin_hash)
            left, total, is_set = get_pin_status(sc)
            self.assertEqual(left, total)
            self.assertEqual(is_set, PIN_UNLOCKED)
        finally:
            sc.request(CMD_PIN_LOCK)
            sc.request(CMD_PIN_UNSET + sha256_pin("correct"))
            sc.close()

    def test_change_pin_hashed(self):
        sc = self.get_secure_channel()
        try:
            ensure_pin_unset(sc)
            old_hash = sha256_pin("oldpin")
            new_hash = sha256_pin("newpin")
            sc.request(CMD_PIN_SET + old_hash)
            sc.request(CMD_PIN_CHANGE + encode(old_hash) + encode(new_hash))
            sc.request(CMD_PIN_LOCK)
            with self.assertRaises(SecureError):
                sc.request(CMD_PIN_UNLOCK + old_hash)
            sc.request(CMD_PIN_UNLOCK + new_hash)
            left, total, is_set = get_pin_status(sc)
            self.assertEqual(is_set, PIN_UNLOCKED)
        finally:
            sc.request(CMD_PIN_LOCK)
            sc.request(CMD_PIN_UNSET + sha256_pin("newpin"))
            sc.close()

    def test_store_and_retrieve_secret(self):
        sc = self.get_secure_channel()
        try:
            ensure_pin_unset(sc)
            secret = os.urandom(64)
            echoed = sc.request(CMD_STORAGE_PUT + secret)
            self.assertEqual(echoed, secret)
            retrieved = sc.request(CMD_STORAGE_GET)
            self.assertEqual(retrieved, secret)
        finally:
            sc.request(CMD_STORAGE_PUT + b"")
            sc.close()

    def test_secret_starts_empty(self):
        sc = self.get_secure_channel()
        try:
            sc.request(CMD_STORAGE_PUT + b"")
            retrieved = sc.request(CMD_STORAGE_GET)
            self.assertEqual(retrieved, b"")
        finally:
            sc.close()

    def test_secret_overwrite(self):
        sc = self.get_secure_channel()
        try:
            secret1 = os.urandom(50)
            secret2 = os.urandom(100)
            sc.request(CMD_STORAGE_PUT + secret1)
            self.assertEqual(sc.request(CMD_STORAGE_GET), secret1)
            sc.request(CMD_STORAGE_PUT + secret2)
            self.assertEqual(sc.request(CMD_STORAGE_GET), secret2)
            self.assertNotEqual(secret1, secret2)
        finally:
            sc.request(CMD_STORAGE_PUT + b"")
            sc.close()

    def test_secret_delete(self):
        sc = self.get_secure_channel()
        try:
            secret = os.urandom(32)
            sc.request(CMD_STORAGE_PUT + secret)
            self.assertEqual(sc.request(CMD_STORAGE_GET), secret)
            sc.request(CMD_STORAGE_PUT + b"")
            self.assertEqual(sc.request(CMD_STORAGE_GET), b"")
        finally:
            sc.request(CMD_STORAGE_PUT + b"")
            sc.close()

    def test_secret_large_payload(self):
        sc = self.get_secure_channel()
        try:
            secret = os.urandom(200)
            echoed = sc.request(CMD_STORAGE_PUT + secret)
            self.assertEqual(echoed, secret)
            self.assertEqual(sc.request(CMD_STORAGE_GET), secret)
        finally:
            sc.request(CMD_STORAGE_PUT + b"")
            sc.close()

    def test_full_specter_diy_roundtrip(self):
        sc = self.get_secure_channel()
        try:
            ensure_pin_unset(sc)
            left, total, is_set = get_pin_status(sc)
            self.assertEqual(is_set, PIN_UNSET)
            ping = sc.request(CMD_ECHO + b"hello")
            self.assertEqual(ping, b"hello")
            rand1 = sc.request(CMD_RAND)
            self.assertEqual(len(rand1), 32)
            rand2 = sc.request(CMD_RAND)
            self.assertNotEqual(rand1, rand2)
            pin = "specter1234"
            pin_hash = sha256_pin(pin)
            sc.request(CMD_PIN_SET + pin_hash)
            left, total, is_set = get_pin_status(sc)
            self.assertEqual(is_set, PIN_UNLOCKED)
            entropy = os.urandom(16)
            fake_aead = b"\x05" + bytes([len(entropy)]) + entropy
            sc.request(CMD_STORAGE_PUT + fake_aead)
            retrieved = sc.request(CMD_STORAGE_GET)
            self.assertEqual(retrieved, fake_aead)
            self.assertIn(entropy, retrieved)
            sc.request(CMD_PIN_LOCK)
            left, total, is_set = get_pin_status(sc)
            self.assertEqual(is_set, PIN_LOCKED)
            with self.assertRaises(SecureError):
                sc.request(CMD_PIN_UNLOCK + sha256_pin("wrongpin"))
            left2, total2, _ = get_pin_status(sc)
            self.assertEqual(left2, left - 1)
            sc.request(CMD_PIN_UNLOCK + pin_hash)
            left, total, is_set = get_pin_status(sc)
            self.assertEqual(is_set, PIN_UNLOCKED)
            self.assertEqual(left, total)
            retrieved2 = sc.request(CMD_STORAGE_GET)
            self.assertEqual(retrieved2, fake_aead)
            new_pin = "newpin5678"
            new_hash = sha256_pin(new_pin)
            sc.request(CMD_PIN_CHANGE + encode(pin_hash) + encode(new_hash))
            sc.request(CMD_PIN_LOCK)
            sc.request(CMD_PIN_UNLOCK + new_hash)
            left, total, is_set = get_pin_status(sc)
            self.assertEqual(is_set, PIN_UNLOCKED)
            retrieved3 = sc.request(CMD_STORAGE_GET)
            self.assertEqual(retrieved3, fake_aead)
            sc.request(CMD_STORAGE_PUT + b"")
            self.assertEqual(sc.request(CMD_STORAGE_GET), b"")
            sc.request(CMD_PIN_LOCK)
            sc.request(CMD_PIN_UNSET + new_hash)
            left, total, is_set = get_pin_status(sc)
            self.assertEqual(is_set, PIN_UNSET)
        finally:
            try:
                sc.request(CMD_STORAGE_PUT + b"")
            except:
                pass
            try:
                ensure_pin_unset(sc)
            except:
                pass
            sc.close()

    def test_multiple_sequential_requests(self):
        sc = self.get_secure_channel()
        try:
            for i in range(20):
                echo = sc.request(CMD_ECHO + bytes([i]))
                self.assertEqual(echo, bytes([i]))
            rand_vals = set()
            for i in range(10):
                r = sc.request(CMD_RAND)
                rand_vals.add(r)
            self.assertEqual(len(rand_vals), 10)
        finally:
            sc.close()

    def test_reopen_channel_after_close(self):
        sc1 = SecureChannel(sim)
        sc1.open()
        echo1 = sc1.request(CMD_ECHO + b"before")
        self.assertEqual(echo1, b"before")
        sc1.close()
        sc2 = SecureChannel(sim)
        sc2.open()
        echo2 = sc2.request(CMD_ECHO + b"after")
        self.assertEqual(echo2, b"after")
        sc2.close()

    def test_channel_auto_reopen(self):
        sc = SecureChannel(sim)
        sc.open()
        echo1 = sc.request(CMD_ECHO + b"first")
        self.assertEqual(echo1, b"first")
        sc.close()
        echo2 = sc.request(CMD_ECHO + b"reopened")
        self.assertEqual(echo2, b"reopened")
        self.assertTrue(sc.is_open)
        sc.close()

    def test_lock_unlock_preserves_secret(self):
        sc = self.get_secure_channel()
        try:
            ensure_pin_unset(sc)
            pin_hash = sha256_pin("testpin")
            secret = os.urandom(48)
            sc.request(CMD_PIN_SET + pin_hash)
            sc.request(CMD_STORAGE_PUT + secret)
            self.assertEqual(sc.request(CMD_STORAGE_GET), secret)
            sc.request(CMD_PIN_LOCK)
            sc.request(CMD_PIN_UNLOCK + pin_hash)
            self.assertEqual(sc.request(CMD_STORAGE_GET), secret)
        finally:
            sc.request(CMD_STORAGE_PUT + b"")
            sc.request(CMD_PIN_LOCK)
            sc.request(CMD_PIN_UNSET + sha256_pin("testpin"))
            sc.close()

if __name__ == '__main__':
    unittest.main()
