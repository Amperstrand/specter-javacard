# Specter-Javacard

JavaCard applets for [Specter-DIY](https://github.com/cryptoadvance/specter-diy) secrets storage.

Documentation for classes and applets is in the [`docs/`](./docs) folder.

Tested on [NXP JCOP3 J3H145](https://www.smartcardfocus.com/shop/ilp/id~879/nxp-j3h145-dual-interface-java-card-144k/p/index.shtml) and [NXP JCOP4 J3R180](https://www.nxp.com/products/security-and-identification/smart-card-ics/secure-element-ics/JCOP4/JCOP4-J3R180-SECID:PJ3R180_V3).

## Applets

| Applet | AID | Description |
|--------|-----|-------------|
| [`Teapot`](./docs/Teapot.md) | `B00B5111CA01` | Simple key-value store, no PIN or secure channel. Good for testing. |
| [`SecureApplet`](./docs/SecureApplet.md) | `B00B5111FF01` | Base class with PIN protection and secure communication. |
| [`MemoryCard`](./docs/MemoryCard.md) | `B00B5111CB01` | Extends `SecureApplet`, arbitrary data storage. Used by specter-diy. |
| [`BlindOracle`](./docs/BlindOracle.md) | `B00B5111CE01` | Extends `SecureApplet`, BIP32 key derivation and signing. |
| [`SingleUseKey`](./docs/SingleUseKey.md) | `B00B5111CD01` | Extends `SecureApplet`, one-time signing key. |

## Getting CAP files

**Primary: download from CI.** Every push to `master` triggers a build that produces reproducible, card-specific CAP files (verified by building twice and comparing SHA-256 hashes after timestamp normalization).

Two artifact sets are produced per build — one compiled for each supported card:

| Artifact | Card | JavaCard SDK |
|----------|------|-------------|
| `cap-files-j3h145` | NXP JCOP3 J3H145 | JC304 |
| `cap-files-j3r180` | NXP JCOP4 J3R180 | JC305 |

1. Go to [Actions](https://github.com/Amperstrand/specter-javacard/actions/workflows/build.yml)
2. Click the latest green run
3. Download the `cap-files-j3h145` or `cap-files-j3r180` artifact for your card

Release assets are named `<Applet>-j3h145.cap` / `<Applet>-j3r180.cap` for easy identification.

## Flashing to card

Requires [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro) (`gp.jar`) and a card reader with `pcscd`:

```sh
sudo apt install pcscd
sudo /usr/sbin/pcscd
java -jar gp.jar --install build/cap/MemoryCardApplet.cap
java -jar gp.jar -l   # verify applet appears
```

Default SCP02 keys: `404142434445464748494A4B4C4D4E4F` (key version 1).

On JCOP4, delete the **package AID** before reinstalling:
```sh
java -jar gp.jar --delete B00B5111CB --force
```

## Building from source

Requires **JDK 8** (JavaCard tooling is incompatible with newer JDKs).

### Nix (recommended)

```sh
nix develop    # provides JDK 8 + ant + ant-javacard
ant all        # produces CAP files in build/cap/
```

### Manual

```sh
git submodule update --init --recursive
# Install JDK 8 and ant for your platform, then:
ant all
```

Build a single applet: `ant MemoryCard`

### Card-specific builds

Use the Makefile targets to compile against each card's native JavaCard SDK:

```sh
make build-j3h145   # NXP JCOP3 J3H145 — compiled with JC304 SDK
make build-j3r180   # NXP JCOP4 J3R180 — compiled with JC305 SDK
```

Or pass the SDK directly to Ant:

```sh
ant all -DJCKIT=sdks/jc304_kit   # J3H145
ant all -DJCKIT=sdks/jc305u3_kit  # J3R180
```

## Running tests

### Simulator

```sh
python3 tests/run_tests.py
```

### Real card

```sh
sudo /usr/sbin/pcscd
cd tests/tests
TEST_MODE=card python3 -m pytest test_specter_diy.py -v
TEST_MODE=card python3 -m pytest test_singleusekey.py -v
TEST_MODE=card python3 -m pytest test_blindoracle.py -v
```

Test files cannot run together in one invocation (they share the card connection). Run them separately.

**Test results on J3R180:** 38/38 passing (15 specter-diy + 10 SingleUseKey + 13 BlindOracle).

## Running benchmarks

```sh
cd tests/tests
TEST_MODE=card python3 benchmark_runner.py --gp-jar ../../gp.jar
```

Run a single applet (skip flashing): `TEST_MODE=card python3 benchmark_runner.py --applet memorycard --skip-flash`

Results are written to `artifacts/benchmarks/<timestamp>-card.json`.

### Benchmark results (J3R180, Gemalto PC Twin Reader, T=1)

| Applet | Operation | Avg (ms) | Min | Max |
|--------|-----------|----------|-----|-----|
| teapot | select | 60.7 | 60.4 | 61.0 |
| teapot | get_default | 59.1 | 59.0 | 59.6 |
| teapot | put_small | 70.9 | 70.4 | 71.0 |
| teapot | put_max | 270.8 | 270.5 | 271.1 |
| teapot | get_after_put | 181.8 | 181.4 | 182.0 |
| memorycard | select | 61.1 | 61.0 | 61.6 |
| memorycard | get_random | 59.7 | 59.4 | 60.0 |
| memorycard | get_pubkey | 62.0 | 62.0 | 62.0 |
| memorycard | sc_open | 232.9 | 232.4 | 233.6 |
| memorycard | sc_echo | 130.0 | 129.9 | 130.1 |
| memorycard | pin_status | 130.3 | 130.0 | 130.6 |
| memorycard | pin_lock | 130.7 | 130.3 | 131.0 |
| memorycard | pin_unlock | 159.7 | 159.4 | 160.0 |
| memorycard | storage_put | 147.4 | 147.0 | 148.0 |
| memorycard | storage_get | 132.8 | 132.4 | 133.1 |
| memorycard | sc_close | 62.6 | 62.4 | 63.0 |
| singleusekey | select | 61.2 | 60.9 | 61.7 |
| singleusekey | generate_key | 96.2 | 96.0 | 96.6 |
| singleusekey | get_pubkey | 61.8 | 61.5 | 62.0 |
| singleusekey | sign_once | 143.0 | 142.6 | 143.4 |
| blindoracle | select | 61.2 | 61.0 | 61.6 |
| blindoracle | sc_open | 257.0 | 256.6 | 257.5 |
| blindoracle | root_set_seed | 228.8 | 228.4 | 229.0 |
| blindoracle | get_root_xpub | 149.7 | 148.4 | 154.0 |
| blindoracle | derive_path | 764.2 | 764.0 | 764.7 |
| blindoracle | get_current_xpub | 148.7 | 148.4 | 149.0 |
| blindoracle | sign_root | 199.8 | 199.3 | 200.1 |
| blindoracle | sign_child | 199.8 | 199.4 | 200.0 |
| blindoracle | derive_and_sign | 787.7 | 787.5 | 788.0 |
| blindoracle | sc_close | 74.2 | 74.0 | 74.5 |

## J3R180 Compatibility

The J3R180 has limited transient RAM (~1500B available). The init system uses a layered approach to avoid pulling in unnecessary heavy crypto:

| Layer | Method | What it allocates | Transient cost |
|-------|--------|-------------------|----------------|
| A | `Crypto.initEssential()` + `Secp256k1.initCore()` | SHA-256, HMAC-SHA256, AES, ECDH (x-only), ECDSA | ~1-1.5 KB |
| B | `FiniteField.initScalar()` | Heap reference only | 0 bytes |
| C | `Secp256k1.initPointOps()` | PLAIN_XY KeyAgreement, tempPrivateKey | ~200-400 B |
| D | `FiniteField.init()` | 7x RSAPublicKey(512) + Cipher | ~2.3-4.6 KB |

### Per-applet layer requirements

| Applet | Layers | J3R180 | J3H145 |
|--------|--------|--------|--------|
| TeapotApplet | None | Yes | Yes |
| MemoryCardApplet | A | Yes | Yes |
| SingleUseKeyApplet | A+B+C | Yes | Yes |
| BlindOracleApplet | A+B+C+SHA-512 | Yes | Yes |

### Key design decisions
- Secure channel signatures use `signNoLowS()` (no FiniteField). Host normalizes S.
- SingleUseKeyApplet defers key generation from constructor to first APDU.
- BlindOracleApplet uses `initScalar()` (Layer B) for scalar math in BIP32 derivation, avoiding the RSA-backed field engine (Layer D).
- All init methods are idempotent and can be called multiple times safely.

## Simulator

A simple way to run the simulator with a particular applet (MemoryCard for example):

```sh
python3 run_sim.py MemoryCard
```

It will spawn the simulator on port `21111` and restart it on every disconnect.

To run `BlindOracle` on port `21111` with AID `B00B5111CE01` directly with `simulator.jar`:

```sh
java -jar "simulator.jar" -p 21111 -a "B00B5111CE01" -c "toys.BlindOracleApplet" -u "file://$PWD/build/classes/BlindOracle/"
```

## Useful links

- https://github.com/OpenCryptoProject/JCMathLib - library for arbitrary elliptic curve operations on javacard
- https://opencryptojc.org/ - making JavaCards open
- https://pyscard.sourceforge.io/ - python tool to talk to smartcards
- https://smartcard-atr.apdu.fr/ - ATR (Answer To Reset) parser
- [keycard.tech](https://keycard.tech/) - JavaCard applet with BIP-32 support
- https://www.youtube.com/watch?v=vd0-Uhx2OoQ - nice talk about JavaCards and open-source ecosystem

## Cards that make sense

Compatibility table: https://www.fi.muni.cz/~xsvenda/jcalgtest/table.html

### Algorithms

`ALG_EC_SVDP_DH_PLAIN` should be there. Many cards support it. Not necessarily `ALG_EC_SVDP_DH_PLAIN_XY`. Required for point multiplication (other than G, i.e. for Schnorr)

`ALG_EC_PACE_GM` is a nice one - allows point addition. AFAIK available only on NXP JCOP3 J3H145 and NXP JCOP4 series.

`TYPE_EC_FP_PRIVATE_TRANSIENT` - useful for bip32 derivation.
Available on:
- Infineon SLE78 JCard
- G&D Smartcafe 7.0
- NXP JCOP4 P71D321
- NXP JCOP4 J3R200
- Taisys SIMoME Vault

`ALG_HMAC_SHA512` - useful for fast PBKDF2 in BIP-39. Available only on Taisys SIMoME Vault

## Don't write your own crypto

But sometimes we have to...
Here we have modulo addition for bip32 key derivation, this one is critical.
For public key uncompression we can use fast functions as no secrets are involved there.

For finite field ariphmetics we are abusing `RSA` encryption coprocessor where we set modulo to `FP` or `N` of `secp256k1` curve and public key to the exponent we need.

Point addition is implemented using `ALG_EC_PACE_GM`, but can be also done manually with a few simple equations over `FP`.

### Rules for crypto

- No branching - `if/switch` statements can leak information through side channels
- Don't do case-via-offset - access time to elements with different indexes can be different
- Use transient arrays when possible - it's orders of magnitude faster than EEPROM
- Use `Key` class when possible, JC platforms secures them better than simple arrays
- Encrypt-then-hmac is the right way to build the secure communiaction channel
- Use ephimerial keys or random nonces when possible, they help against replay attacks
