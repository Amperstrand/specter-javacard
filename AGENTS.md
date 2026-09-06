# AGENTS.md

## Card Reader

Gemalto PC Twin Reader (BCF852F0) 00 00

## Identifying Cards

Each card has a unique IC Serial Number burned into the chip at fabrication, readable without authentication via CPLC data (`gp.jar -d --info`). This serial could be used for per-card key derivation (EMV/VISA2 KDF) if a master key is shared across multiple cards. Comparison of all known cards:

| Property | J3R180 #1 (stickered) | J3R180 #2 (unstickered) | J3H145 |
|---|---|---|---|
| **IC Serial** | `50879920` | `50920920` | `06251320` |
| **IC Batch** | `6782` | `6782` | `7448` |
| **Pre-personalizer** | `1612` | `161C` | `0343` |
| **Key version** | 255 (factory) | 1 (default) | 1 (unknown) |

## J3R180 Card #1 — "stickered" (ATR: 3BD518FF8191FE1FC38073C821100A)

- Chip: NXP P71D321 (SmartMX3), JCOP4
- Fabrication: 2013-05-09, Serial: 50879920, Batch: 6782
- Pre-personalizer: 1612, Equipment: 38373939
- GlobalPlatform 2.3, JavaCard v3
- SCP02 only (i=15, i=35, i=55, i=75)
- State: OP_READY (factory state, key-ver 255)
- Factory/transport keys (key-ver 0):

```
KEY_ENC=5A9E63D03BADBC2A240FE8F534709EDF
KEY_MAC=7CCC1E79D64FC5FA263B8F2955282998
KEY_DEK=B040703EC3DE23EE8AE4CFB6D632AA80
```

- gp.jar invocation: `java -jar gp.jar --key-enc 5A9E63D03BADBC2A240FE8F534709EDF --key-mac 7CCC1E79D64FC5FA263B8F2955282998 --key-dek B040703EC3DE23EE8AE4CFB6D632AA80 --key-ver 0`
- Status: Fully working, factory keys verified (key-ver 0)
- Installed apps (pre-loaded, survived factory reset):
  - `A000000151535041` — GP ISD Support
  - `5361746F44696D6500` — SatoDim v0.1
  - `D276000124010304AFAF000000000000` — OpenPGP v1.0 (serial AFAF000000000000)
  - `A000000308000010000100` — PIV Card v1.0
  - `A00000016443446F634C69746501` — d34d4cLite v1.0
  - GP support packages (v1.3, v1.0)
- NOTE: Previously had default key `404142434445464748494A4B4C4D4E4F` at key-ver 1 and all 4 specter-diy applets installed (confirmed by benchmark on 2026-03-20). Was externally factory-reset between 2026-03-20 and 2026-03-21 — specter-diy applets wiped, keys reverted to factory/transport. gp_helper.py defaults do NOT work on this card.

## J3R180 Card #2 — unstickered (ATR: 3BD518FF8191FE1FC38073C821100A)

- Chip: NXP P71D321 (SmartMX3), JCOP4
- Fabrication: 2013-05-09, Serial: 50920920, Batch: 6782
- Pre-personalizer: 161C (date: 2018-05-10), Equipment: 39323039
- GlobalPlatform 2.3, JavaCard v3
- SCP02 only (i=15, i=35, i=55, i=75)
- State: INITIALIZED (personalized, key-ver 1)
- Keys (key-ver 1): `404142434445464748494A4B4C4D4E4F` (default, verified working)
- gp.jar invocation: `java -jar gp.jar --key 404142434445464748494A4B4C4D4E4F --key-ver 1`
- Status: Fully working, default keys verified
- Installed apps (pre-loaded):
  - `A000000151535041` — GP ISD Support
  - `5361746F44696D6500` — SatoDim v0.1
  - `5361746F4368697000` — SatoChip v0.1
  - `A000000308000010000100` — PIV Card v1.0
- NOTE: Factory keys (key-ver 0) do NOT work on this card. Use default keys at key-ver 1.

## J3H145 Card (ATR: 3BFA1800008131FE454A546178436F72655631B2)

- Chip: NXP P71D321 (SmartMX3), JCOP3
- Fabrication: 2013-06-17, Serial: 06251320, Batch: 7448
- Pre-personalizer: 0343, Equipment: 32353133
- GlobalPlatform 2.3, JavaCard v3
- SCP02 only (i=15, i=35, i=55, i=75)
- Key version 1 (personalized, not factory)
- Status: LOCKED — keys unknown, card functional but cannot be managed

### Installed applets (confirmed via read-only SELECT probes)

| AID | Name | Version |
|-----|------|---------|
| `536565644b656570657200` | **Seedkeeper** | v0.1 |
| `D276000124010304AFAF000000000000` | **OpenPGP** | v1.0 (serial AFAF000000000000) |
| `A000000308000010000100` | **PIV Card** | v1.0 |
| `A0000000620202` | GP support PKG | v1.3 |
| `A0000000620204` | GP support PKG | v1.0 |
| `A000000151535041` | GP ISD Support | — |

### NOT installed (confirmed via SELECT probes)

- All specter-diy applets (Teapot, MemoryCard, SingleUseKey, BlindOracle)
- SatoChip, SatoDim
- No evidence of specter-diy ever being installed (no benchmark/test artifacts exist for this card)

### Key authentication attempts (2026-03-21)

| Keys used | Key-ver | Result |
|-----------|---------|--------|
| `404142434445464748494A4B4C4D4E4F` (default, single key) | 1 | Card cryptogram mismatch |
| `5A9E63D0...` / `7CCC1E79...` / `B040703E...` (J3R180 factory ENC/MAC/DEK) | 1 | Card cryptogram mismatch |

### WARNING: 3 failed auth attempts consumed out of ~5-15 total.

DO NOT retry authentication until correct keys are confirmed. Exhausting the retry counter will permanently block the card's key slots. The keys were likely set by the Seedkeeper/Satochip deployment tooling. Check Satochip documentation or whoever deployed Seedkeeper on this card for the personalization keys.

## GP Card Lifecycle States

GlobalPlatform defines these states (in order):

1. **OP_READY** — Factory state. Card Manager exists with factory/transport keys. No issuer has personalized it. Blank device from the factory.
2. **INITIALIZED** — Personalized. Custom keys and key version set. Ready for applet deployment. Cannot revert to OP_READY without a factory reset (which wipes applets and reverts keys to transport values).
3. **SECURED** — Card issuer has loaded mandatory domain-specific data and policies.
4. **CARD_LOCKED** — Card is locked due to administrative action or security violation. Selectable applets may still function but no GP management operations are allowed.
5. **TERMINATED** — Card is permanently terminated. No operations possible.

Transition from OP_READY → INITIALIZED is done by setting new keys (e.g., `gp.jar --put-key`). A factory reset reverses this but wipes all installed applets.

## General GP Commands

```sh
# List installed applets (read-only after auth)
java -jar gp.jar --key-enc <enc> --key-mac <mac> --key-dek <dek> --key-ver <ver> -d --list

# Install CAP file
java -jar gp.jar --key-enc <enc> --key-mac <mac> --key-dek <dek> --key-ver <ver> -d --install <file.cap>

# Delete package
java -jar gp.jar --key-enc <enc> --key-mac <mac> --key-dek <dek> --key-ver <ver> -d --delete <aid> --force

# Get card info (unauthenticated)
java -jar gp.jar -d --info
```

## KCV Warning

gp.jar emits "Don't know how to calculate KCV, defaulting to SCP02" when using raw hex keys. This is harmless and does not affect authentication.

## Safety Notes

- benchmark_runner.py calls gp.jar directly without CardKeyGuard protection
- gp_helper.py has key blacklist protection — prefer it over direct gp.jar calls
- Each failed SCP02 auth attempt permanently consumes one retry counter on the card
- JCOP cards typically allow 5-15 retries before key slots are permanently blocked
- SELECT commands are safe and read-only — they do NOT consume retry counters
- Only INITIALIZE UPDATE (8050) consumes retry counters on failed auth

## External posting (owner directive 2026-09-06 — CHANNEL rule)

Agents never post on non-member repos — no `gh` writes (issues, PRs,
comments, reviews, gists), not even with per-text owner sign-off; the
owner does the copy-paste into GitHub themselves. Member orgs (verify:
`gh api user/orgs`; 2026-09-06: Amperstrand, OpenTollGate, net4sats,
FreedomTechFeed) keep the existing owner-gate flow. Read the target
repo CONTRIBUTING/AI policy before drafting anything upstream.
Canonical text: lightning-playground AGENTS.md (standing rule UPDATE
2026-09-06).
