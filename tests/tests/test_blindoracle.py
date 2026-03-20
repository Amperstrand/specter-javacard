#!/usr/bin/env python3
import unittest, os
from util.securechannel import SecureChannel, SecureError
from util import secp256k1

AID = "B00B5111CE01"
APPLET = "toys.BlindOracleApplet"
CLASSDIR = "BlindOracle"

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

SEED = bytes.fromhex("ae361e712e3fe66c8f1d57192d80abe076137c917d37cee7da8ed152e993226df0ced36f35c0967f96a5291f35035e87be9b3df626e6eb96ad2b59fbd9c503f4")
ROOT_XPRV = bytes.fromhex("5d85539e0995941e1dafd9fc27df3efea381461c13cfd245137b43bb37c29c39004cfa6a4f047f2c3fcad170a3a5f0ef254f0bbe2b2bec7554043c145dcc779428")
EXPECTED_ROOT_XPUB = bytes.fromhex("5d85539e0995941e1dafd9fc27df3efea381461c13cfd245137b43bb37c29c39025a94ecdc430e6508ea7a432d1ae30e1d656194a028848f652a08bc43439b8561")
PATH_44H_0H_1H_0_55 = [44+0x80000000, 0x80000000, 0x80000001, 0, 55]
BPATH_FULL = b"".join(p.to_bytes(4,'big') for p in PATH_44H_0H_1H_0_55)
EXPECTED_CHILD_XPUB = bytes.fromhex("3902805bec66b8546bae3984ee186dd9d9620cead3d242bf8893e984aa472912033156b64844e8ce5f3d1d52092c9809a75bcbac93bfc9fc5b3a543842fb4d3558")
MSG = b"5"*32

def encode(data):
    return bytes([len(data)])+data

class BlindOracleAppletTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_secure_channel(self, open=True):
        sc = SecureChannel(sim)
        sc.open()
        self.assertEqual(sc.is_open, True)
        return sc

    def _init_from_seed(self, sc):
        res = sc.request(b"\x10\x00"+SEED)
        self.assertEqual(res, EXPECTED_ROOT_XPUB)
        return res

    def test_select(self):
        data = SELECT+encode(bytes.fromhex(AID))
        res = sim.request(data)
        self.assertEqual(res, b"")

    def test_root_set_seed(self):
        sc = self.get_secure_channel()
        res = sc.request(b"\x10\x00"+SEED)
        self.assertEqual(res, EXPECTED_ROOT_XPUB)
        sc.close()

    def test_root_set_xprv(self):
        sc = self.get_secure_channel()
        res = sc.request(b"\x10\x01"+ROOT_XPRV)
        self.assertEqual(res, EXPECTED_ROOT_XPUB)
        sc.close()

    def test_root_set_random(self):
        sc = self.get_secure_channel()
        res = sc.request(b"\x10\x7d")
        self.assertEqual(len(res), 65)
        self.assertTrue(res[32] >= 2 and res[32] <= 3)
        sc.close()

    def test_get_root_xpub(self):
        sc = self.get_secure_channel()
        self._init_from_seed(sc)
        res = sc.request(b"\x11\x00")
        self.assertEqual(res, EXPECTED_ROOT_XPUB)
        sc.close()

    def test_derive_hardened_path(self):
        sc = self.get_secure_channel()
        self._init_from_seed(sc)
        res = sc.request(b"\x11\x01"+b"\x00"+BPATH_FULL)
        self.assertEqual(res, EXPECTED_CHILD_XPUB)
        sc.close()

    def test_derive_incremental(self):
        sc = self.get_secure_channel()
        self._init_from_seed(sc)
        res = sc.request(b"\x11\x01"+b"\x00"+BPATH_FULL[:8])
        res = sc.request(b"\x11\x01"+b"\x01"+BPATH_FULL[8:])
        self.assertEqual(res, EXPECTED_CHILD_XPUB)
        sc.close()

    def test_get_current_xpub(self):
        sc = self.get_secure_channel()
        self._init_from_seed(sc)
        sc.request(b"\x11\x01"+b"\x00"+BPATH_FULL)
        res = sc.request(b"\x11\x02")
        self.assertEqual(res, EXPECTED_CHILD_XPUB)
        sc.close()

    def test_sign_root(self):
        sc = self.get_secure_channel()
        self._init_from_seed(sc)
        sec = bytes.fromhex("025a94ecdc430e6508ea7a432d1ae30e1d656194a028848f652a08bc43439b8561")
        pub = secp256k1.ec_pubkey_parse(sec)
        res = sc.request(b"\x11\x03"+MSG+b"\x00")
        sig = secp256k1.ecdsa_signature_parse_der(res)
        sig = secp256k1.ecdsa_signature_normalize(sig)
        self.assertTrue(secp256k1.ecdsa_verify(sig, MSG, pub))
        sc.close()

    def test_sign_child(self):
        sc = self.get_secure_channel()
        self._init_from_seed(sc)
        sc.request(b"\x11\x01"+b"\x00"+BPATH_FULL)
        sec = bytes.fromhex("033156b64844e8ce5f3d1d52092c9809a75bcbac93bfc9fc5b3a543842fb4d3558")
        pub = secp256k1.ec_pubkey_parse(sec)
        res = sc.request(b"\x11\x03"+MSG+b"\x01")
        sig = secp256k1.ecdsa_signature_parse_der(res)
        sig = secp256k1.ecdsa_signature_normalize(sig)
        self.assertTrue(secp256k1.ecdsa_verify(sig, MSG, pub))
        sc.close()

    def test_derive_and_sign(self):
        sc = self.get_secure_channel()
        self._init_from_seed(sc)
        sc.request(b"\x11\x01"+b"\x00"+BPATH_FULL[:8])
        sec = bytes.fromhex("033156b64844e8ce5f3d1d52092c9809a75bcbac93bfc9fc5b3a543842fb4d3558")
        pub = secp256k1.ec_pubkey_parse(sec)
        res = sc.request(b"\x11\x04"+MSG+b"\x01"+BPATH_FULL[8:])
        sig = secp256k1.ecdsa_signature_parse_der(res)
        sig = secp256k1.ecdsa_signature_normalize(sig)
        self.assertTrue(secp256k1.ecdsa_verify(sig, MSG, pub))
        sc.close()

    def test_derive_and_sign_preserves_current(self):
        sc = self.get_secure_channel()
        self._init_from_seed(sc)
        sc.request(b"\x11\x01"+b"\x00"+BPATH_FULL[:8])
        current = sc.request(b"\x11\x02")
        sc.request(b"\x11\x04"+MSG+b"\x01"+BPATH_FULL[8:])
        res = sc.request(b"\x11\x02")
        self.assertEqual(res, current)
        sc.close()

    def test_seed_consistency(self):
        sc = self.get_secure_channel()
        self._init_from_seed(sc)
        root1 = sc.request(b"\x11\x00")
        sc.request(b"\x11\x01"+b"\x00"+BPATH_FULL)
        child1 = sc.request(b"\x11\x02")
        sec = bytes.fromhex("033156b64844e8ce5f3d1d52092c9809a75bcbac93bfc9fc5b3a543842fb4d3558")
        pub = secp256k1.ec_pubkey_parse(sec)
        sig1 = secp256k1.ecdsa_signature_parse_der(
            sc.request(b"\x11\x03"+MSG+b"\x01"))
        sc.request(b"\x10\x00"+SEED)
        root2 = sc.request(b"\x11\x00")
        sc.request(b"\x11\x01"+b"\x00"+BPATH_FULL)
        child2 = sc.request(b"\x11\x02")
        sig2 = secp256k1.ecdsa_signature_parse_der(
            sc.request(b"\x11\x03"+MSG+b"\x01"))
        self.assertEqual(root1, root2)
        self.assertEqual(child1, child2)
        self.assertTrue(secp256k1.ecdsa_verify(sig1, MSG, pub))
        self.assertTrue(secp256k1.ecdsa_verify(sig2, MSG, pub))
        sc.close()

    def test_ecdsa_nonce_uniqueness(self):
        sc = self.get_secure_channel()
        self._init_from_seed(sc)
        sec = bytes.fromhex("025a94ecdc430e6508ea7a432d1ae30e1d656194a028848f652a08bc43439b8561")
        pub = secp256k1.ec_pubkey_parse(sec)
        sig1 = secp256k1.ecdsa_signature_parse_der(
            sc.request(b"\x11\x03"+MSG+b"\x00"))
        sig2 = secp256k1.ecdsa_signature_parse_der(
            sc.request(b"\x11\x03"+MSG+b"\x00"))
        r1 = secp256k1.ecdsa_signature_serialize_compact(sig1)[:32]
        r2 = secp256k1.ecdsa_signature_serialize_compact(sig2)[:32]
        self.assertNotEqual(r1, r2, "ECDSA nonces must be unique — same r value detected")
        self.assertTrue(secp256k1.ecdsa_verify(sig1, MSG, pub))
        self.assertTrue(secp256k1.ecdsa_verify(sig2, MSG, pub))
        sc.close()

if __name__ == '__main__':
    unittest.main()
