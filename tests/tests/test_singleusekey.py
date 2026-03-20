#!/usr/bin/env python3
import unittest, os, hashlib
from util.securechannel import SecureChannel, SecureError
from util import secp256k1

AID = "B00B5111CD01"
APPLET = "toys.SingleUseKeyApplet"
CLASSDIR = "SingleUseKey"

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

INS_SINGLE_USE_KEY = 0xA0
SUBCMD_GENERATE     = 0x00
SUBCMD_GET_PUBKEY   = 0x01
SUBCMD_SIGN         = 0x02

CMD_SINGLE_USE_KEY = 0x20

def encode(data):
    return bytes([len(data)])+data

class SingleUseKeyAppletTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_secure_channel(self, open=True):
        sc = SecureChannel(sim)
        sc.open()
        self.assertEqual(sc.is_open, True)
        return sc

    def test_select(self):
        data = SELECT+encode(bytes.fromhex(AID))
        res = sim.request(data)
        self.assertEqual(res, b"")

    def test_generate_key_plaintext(self):
        pub = sim.request(bytes([0x00, INS_SINGLE_USE_KEY, SUBCMD_GENERATE, 0x00]))
        self.assertEqual(len(pub), 33)
        self.assertIn(pub[0], [0x02, 0x03])

    def test_get_pubkey_plaintext(self):
        sim.request(bytes([0x00, INS_SINGLE_USE_KEY, SUBCMD_GENERATE, 0x00]))
        pub = sim.request(bytes([0x00, INS_SINGLE_USE_KEY, SUBCMD_GET_PUBKEY, 0x00]))
        self.assertEqual(len(pub), 33)
        self.assertIn(pub[0], [0x02, 0x03])

    def test_sign_plaintext(self):
        sim.request(bytes([0x00, INS_SINGLE_USE_KEY, SUBCMD_GENERATE, 0x00]))
        pub_bytes = sim.request(bytes([0x00, INS_SINGLE_USE_KEY, SUBCMD_GET_PUBKEY, 0x00]))
        msg_hash = hashlib.sha256(b"test message").digest()
        sig = sim.request(bytes([0x00, INS_SINGLE_USE_KEY, SUBCMD_SIGN, 0x00]) + encode(msg_hash))
        self.assertGreater(len(sig), 0)
        pub = secp256k1.ec_pubkey_parse(pub_bytes)
        parsed_sig = secp256k1.ecdsa_signature_parse_der(sig)
        parsed_sig = secp256k1.ecdsa_signature_normalize(parsed_sig)
        self.assertTrue(secp256k1.ecdsa_verify(parsed_sig, msg_hash, pub))

    def test_key_rotates_after_sign(self):
        sim.request(bytes([0x00, INS_SINGLE_USE_KEY, SUBCMD_GENERATE, 0x00]))
        pub1 = sim.request(bytes([0x00, INS_SINGLE_USE_KEY, SUBCMD_GET_PUBKEY, 0x00]))
        msg_hash = hashlib.sha256(b"test message").digest()
        sim.request(bytes([0x00, INS_SINGLE_USE_KEY, SUBCMD_SIGN, 0x00]) + encode(msg_hash))
        pub2 = sim.request(bytes([0x00, INS_SINGLE_USE_KEY, SUBCMD_GET_PUBKEY, 0x00]))
        self.assertNotEqual(pub1, pub2)

    def test_key_rotates_after_generate(self):
        sim.request(bytes([0x00, INS_SINGLE_USE_KEY, SUBCMD_GENERATE, 0x00]))
        pub1 = sim.request(bytes([0x00, INS_SINGLE_USE_KEY, SUBCMD_GET_PUBKEY, 0x00]))
        sim.request(bytes([0x00, INS_SINGLE_USE_KEY, SUBCMD_GENERATE, 0x00]))
        pub2 = sim.request(bytes([0x00, INS_SINGLE_USE_KEY, SUBCMD_GET_PUBKEY, 0x00]))
        self.assertNotEqual(pub1, pub2)

    def test_sc_generate_key(self):
        sc = self.get_secure_channel()
        res = sc.request(bytes([CMD_SINGLE_USE_KEY, SUBCMD_GENERATE]))
        self.assertEqual(len(res), 33)
        self.assertIn(res[0], [0x02, 0x03])
        sc.close()

    def test_sc_get_pubkey(self):
        sc = self.get_secure_channel()
        sc.request(bytes([CMD_SINGLE_USE_KEY, SUBCMD_GENERATE]))
        pub = sc.request(bytes([CMD_SINGLE_USE_KEY, SUBCMD_GET_PUBKEY]))
        self.assertEqual(len(pub), 33)
        self.assertIn(pub[0], [0x02, 0x03])
        sc.close()

    def test_sc_sign_once(self):
        sc = self.get_secure_channel()
        sc.request(bytes([CMD_SINGLE_USE_KEY, SUBCMD_GENERATE]))
        pub_bytes = sc.request(bytes([CMD_SINGLE_USE_KEY, SUBCMD_GET_PUBKEY]))
        msg_hash = hashlib.sha256(b"secure message").digest()
        sig = sc.request(bytes([CMD_SINGLE_USE_KEY, SUBCMD_SIGN]) + msg_hash)
        self.assertGreater(len(sig), 0)
        pub = secp256k1.ec_pubkey_parse(pub_bytes)
        parsed_sig = secp256k1.ecdsa_signature_parse_der(sig)
        parsed_sig = secp256k1.ecdsa_signature_normalize(parsed_sig)
        self.assertTrue(secp256k1.ecdsa_verify(parsed_sig, msg_hash, pub))
        sc.close()

    def test_invalid_p1(self):
        with self.assertRaises(ISOException) as e:
            sim.request(bytes([0x00, INS_SINGLE_USE_KEY, 0x03, 0x00]))

if __name__ == '__main__':
    unittest.main()
