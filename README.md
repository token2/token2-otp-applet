# token2-otp-applet

**Token2 OTP applet for NXP-based FIDO2 security keys and cards**

A Java Card applet implementing an on-device TOTP/HOTP store that speaks
the open
[Token2 OTP management protocol](https://github.com/token2/token2-otp-cli/blob/main/docs/Token2-OTP-SDK-Protocol.md),
so it can be provisioned and read by the
[token2-otp-cli](https://github.com/token2/token2-otp-cli) tool over any
PC/SC reader (USB contact reader or NFC reader).

> ## ⚠️ TOTP IS **NOT** PHISHING RESISTANT
>
> **A one-time code can be phished, relayed, and replayed in real time by a
> proxy site just like a password. Only FIDO2/WebAuthn provides
> phishing-resistant authentication. Use the OTP functionality for legacy
> services only; wherever FIDO2 is available, use FIDO2.**

## Target hardware

This code runs on real Token2 hardware: FIDO2 security keys and cards built
on NXP secure-element chips, where it is deployed as an additional applet
alongside the FIDO2 applet on the same chip. Some Token2 device models use
different (but mostly NXP-alike) Java Card chips; on those, minor
modifications may be required — typically the AES key/`Cipher` allocation
flags, transient-memory sizing, or the EC keypair setup, depending on what
the particular chip's crypto co-processor exposes. Blank NXP JCOP developer
cards (J3H145, J3R180, and similar) work as well and are a convenient test
target.

## Scope: which Token2 product line is this for?

- **This is NOT for the standalone TOTP hardware tokens** — the classic
  programmable tokens with an LCD screen and a battery. Those run different
  firmware; refer to the
  [token2/openT2OTP](https://github.com/token2/openT2OTP) repository for
  that product line.
- **This IS the extra OTP applet** that runs on the same device as the
  FIDO2 applet(s) — i.e. the multi-applet security keys/cards. The FIDO2
  applet itself is also open source; see the
  [token2/pin_plus_firmware](https://github.com/token2/pin_plus_firmware)
  repository (Token2 PIN+ FIDO2 applet source code).

## Why we are open-sourcing this now

We have decided to open most of our code — both software (host-side tools
such as [token2-otp-cli](https://github.com/token2/token2-otp-cli) and
[fido2-manage](https://github.com/token2/fido2-manage)) and firmware (the
device-side applets, starting with the
[PIN+ FIDO2 applet](https://github.com/token2/pin_plus_firmware) and now
this OTP applet). Making the code publicly available allows independent
review and research, and contributes to the broader community of security
key developers.

This is **existing code, not a rewrite** — we are simply making it public.
As is usual practice when opening a codebase, it was cleaned up before
publication: debug test routines were removed, and the comments — originally
written in French — were removed and replaced with English documentation.
None of the cleanup changes the applet's behavior; the published code passes
the same cross-validation checks against the CLI as described below.

## What is implemented

| Command | APDU | Status |
|---|---|---|
| SELECT applet | `00 A4 04 00` + AID `F00000014F747001` | ✅ |
| GET_ECDH_PUBKEY | `80 C5 01 00` | ✅ P-256, raw `X‖Y` |
| WRITE_SEED (write / delete / erase-all) | `80 C5 05 02` | ✅ ECDH + SHA-256 + AES-256-CBC, IV-1, PKCS#7 |
| ENUM_CODES READ_ALL (paginated) | `80 C5 05 00`, sub `03` | ✅ partial-bit pagination |
| ENUM_CODES READ_ONE | `80 C5 05 00`, sub `01` | ✅ always includes the code |
| ENUM_CODES GET_METADATA | `80 C5 05 00`, sub `02` | ✅ code only |
| ENUM_CODES_CONTINUE | `80 C5 05 01` | ✅ |
| READ_CONFIG | `80 C5 02 00` | ✅ reports NFC+CCID, TOTP supported, no button-HOTP |
| ENABLE_TOTP | `80 C5 02 05` | ✅ stored flag |
| SET_DEVICE_TYPE | `80 C5 02 01` | accepted as a no-op (a card has no USB composite interfaces to disable, so the protocol's bricking foot-gun doesn't exist here) |
| WRITE_HOTP_SEED / CFG_HOTP_* | `80 C5 00 00`, `80 C5 02 02/04/06` | returns `6A86` (HID not supported) — a smartcard has no keyboard interface; the CLI treats this as an expected model limitation |
| GET_INFO / serial number | `80 33 00 00` | ✅ random 5-byte serial generated at install |

OTP engine: HOTP per RFC 4226 and TOTP per RFC 6238, HMAC-SHA1 and
HMAC-SHA256, 4–10 digit codes, configurable time-step, per-entry HOTP
counters persisted with transactional increments. The card has no clock,
so — exactly like the real token — the host supplies the UNIX timestamp in
each read request and the card computes `counter = timestamp / timestep`.

Capacity: 32 entries (change `MAX_ENTRIES`; each slot costs 210 bytes of
persistent memory).

## Card requirements

- Java Card **3.0.4+** with **extended-length APDU** support
- ECC **P-256** with `KeyAgreement.ALG_EC_SVDP_DH_PLAIN`
- **AES-256** CBC
- **32-bit int** support (the CAP is converted with `-i`)

All of these are standard on the NXP secure elements used in Token2 devices
and on NXP JCOP 3 / JCOP 4 developer cards (e.g. J3H145 / J3R180). Very old
J2A parts may lack AES-256 or `DH_PLAIN`; NXP-alike chips from other vendors
may need the minor modifications mentioned above.

## Building

A prebuilt `t2otp.cap` (target: Java Card 3.0.5) is included; it passed the
Oracle off-card verifier with 0 errors. To rebuild:

```bash
# 1. Get a Java Card SDK bundle
git clone https://github.com/martinpaljak/oracle_javacard_sdks sdks

# 2. Compile (JDK 8+; class files must be -release 8 for the 3.2 converter)
javac --release 8 -cp sdks/jc320v26.0_kit/lib/api_classic-3.0.5.jar \
      -d classes src/t2otp/Token2OtpApplet.java

# 3. Convert to CAP (note the -i flag: the applet uses 32-bit int)
JC_HOME=$PWD/sdks/jc320v26.0_kit sh sdks/jc320v26.0_kit/bin/converter.sh \
  -i -classdir classes -target 3.0.5 \
  -applet 0xF0:0x00:0x00:0x01:0x4F:0x74:0x70:0x01 t2otp.Token2OtpApplet \
  -out CAP EXP JCA -d cap \
  t2otp 0xF0:0x00:0x00:0x01:0x4F:0x74:0x70 1.0
```

Alternatively use [ant-javacard](https://github.com/martinpaljak/ant-javacard)
with the included `build.xml` (drop `ant-javacard.jar` into `lib/`).

## Installing on the card

Use [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro)
with your PC/SC reader:

```bash
gp --install t2otp.cap
gp --list       # should show applet F00000014F747001
```

This assumes the card still has default GlobalPlatform test keys
(`404142...4F`), which blank JCOP dev cards from the usual resellers do.
**If your card has custom ISD keys, three wrong authentication attempts can
permanently lock the card manager** — know your keys before you `gp`.

## Using it with token2-otp-cli

Place the card on the reader and use the CLI exactly as documented — it
auto-detects PC/SC:

```bash
python3 app.py write_entry --app-name "Test app" --account-name "alice" \
    --seed JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP
python3 app.py get_all
python3 app.py read_entry --app-name "Test app" --account-name "alice"
python3 app.py erase_all
```

### Serial number over PC/SC (optional)

The CLI reads the serial via the *FIDO* applet AID
(`A0 00 00 06 47 2F 00 01`), not the OTP AID. If you want
`read_serial_no` to work, install a **second instance** of this applet
under that AID:

```bash
gp --package F00000014F7470 --applet F00000014F747001 \
   --create A0000006472F0001
```

Only do this if the card does not already host a real FIDO applet at that
AID (e.g. Vivokey/OpenJavaCard FIDO2 installs) — AIDs must be unique.

## Verification against the Python CLI

The applet's algorithms were cross-validated (`test/cross_check.py`) by
mirroring them 1:1 in Python and driving them with the **unmodified CLI
code** from token2-otp-cli (`token2/ecdh_enc.py`, `token2/data_structures.py`,
`token2/__init__.py`). All 19 checks pass:

- **Provisioning round trip**: a `WRITE_SEED` blob produced by the CLI's own
  `encrypt_payload_ecdh()` (ephemeral P-256 → shared X → SHA-256 → AES-256-CBC
  with IV-1 → PKCS#7) decrypts and parses to the exact cleartext, including
  the delete case (`seed_len == 0` with a zero algorithm byte — the applet
  deliberately checks `seed_len` *before* validating the algorithm, because
  the CLI's `DeleteOTPEntry` serializes `alg = 0x00`).
- **TOTP counter**: the applet's byte-wise u64÷u16 long division matches
  native integer division for edge cases up to 2⁶⁴−1 and timestep 65535,
  including timestamps past 2038.
- **HMAC**: the applet's manual ipad/opad construction matches `hmac` for
  SHA-1 and SHA-256 across key lengths 1–64.
- **RFC vectors**: all RFC 4226 Appendix D HOTP codes and all RFC 6238
  Appendix B TOTP codes (SHA-1 and SHA-256, 8 digits) reproduce exactly.
- **Wire format**: records emitted by the applet parse correctly through the
  CLI's own `EnumOTPEntry.unserialize()` in both modes — `READ_ONE`
  (`full_decode=True`, code always present) and `READ_ALL` (HOTP/button
  entries masked, partial-page flag in bit 7 of the first byte, stripped by
  the CLI's `_extract_partial_flag`). Request offsets and the `GET_INFO`
  `D1 10 || 00×16` framing were checked against the CLI serializers.

The CAP itself was built with the Oracle Java Card 3.2 converter targeting
platform 3.0.5 and passes the Oracle off-card bytecode verifier with
0 errors.

## Reproducing on an NXP card — step by step

Tested build path (any Linux/macOS/Windows host with a PC/SC reader):

```bash
# 0. A blank NXP Java Card, e.g.:
#    - NXP J3H145 (SmartMX2 P60, JCOP 3, dual-interface)
#    - NXP J3R180 (SmartMX3 P71, JCOP 4, dual-interface)
#    both sold blank by the usual smartcard resellers, with default GP keys.

# 1. Install GlobalPlatformPro and check the card responds
gp --info
#    -> shows JCOP version, free EEPROM, default ISD

# 2. Load the applet (prebuilt CAP included in this repo)
gp --install t2otp.cap
gp --list
#    -> APP: F00000014F747001 (SELECTABLE)

# 3. Optional: second instance under the FIDO AID so read_serial_no works
#    (skip if a real FIDO2 applet is installed at that AID)
gp --package F00000014F7470 --applet F00000014F747001 \
   --create A0000006472F0001

# 4. Use the unmodified CLI (it auto-detects PC/SC readers)
git clone https://github.com/token2/token2-otp-cli && cd token2-otp-cli
pip install -r requirements.txt

python3 app.py write_entry --app-name "Test app" --account-name "alice" \
    --seed JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP
python3 app.py write_entry --app-name "Legacy VPN" --account-name "bob" \
    --type hotp --algorithm sha256 --seed JBSWY3DPEHPK3PXP
python3 app.py get_all
#    [TOTP/SHA1/30s] Test app / alice - 123456
#    [HOTP/SHA256] Legacy VPN / bob - ********      <- masked, as designed
python3 app.py read_entry --app-name "Legacy VPN" --account-name "bob"
#    -> returns the HOTP code and advances the on-card counter
python3 app.py delete_entry --app-name "Test app" --account-name "alice"
python3 app.py erase_all
```

Cross-check a returned TOTP code independently on the host:

```bash
python3 -c "import pyotp; print(pyotp.TOTP('JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP').now())"
```

Interop notes observed from the CLI source:

- Over PC/SC the CLI SELECTs the OTP AID with a **short** APDU and then
  sends every command with an **extended Lc and no Le** (ISO case 3E). NXP
  JCOP returns response data on T=1/T=CL regardless of the absent Le; the
  applet implements `javacardx.apdu.ExtendedLength`, which is required.
- `read_serial_no` first SELECTs the FIDO AID `A0000006472F0001` and only
  handles connection errors — if nothing is installed at that AID the CLI
  exits with an unhandled `BadStatusCode`; hence the optional step 3.
- Devices with different (but mostly NXP-alike) chips: if `gp --install`
  or the first `write_entry` fails, the usual suspects are AES-256
  transient-key support (the constructor already falls back to a persistent
  key object), `ALG_EC_SVDP_DH_PLAIN` availability, and extended-APDU
  support over the contactless interface — adjust those allocations first.

## Behavioral notes & limitations

- **No button on cards.** The protocol itself anticipates this: over PC/SC "a touch
  is implicit" (presenting the card to the reader *is* the user action), so
  `READ_ONE` always returns the code, including for button-required and
  HOTP entries. `READ_ALL` still masks those entries on the wire, exactly
  like the real token, so the CLI output looks identical.
- **Overwriting an entry resets its HOTP counter** (new seed ⇒ counter 0).
- **`ENABLE_TOTP` is stored and reflected in `READ_CONFIG`** but not
  enforced against writes — the CLI never gates on it.
- **Seed-at-rest security**: seeds live in persistent memory behind the
  certified secure-element OS, but the OTP applet is not PIN-gated by
  design — anyone with physical possession can read codes over NFC. OTP is
  always used together with an account password, and — per the warning at
  the top — **TOTP IS NOT PHISHING RESISTANT**. Reserve it for legacy
  services and use the FIDO2 applet everywhere else.
- The fixed AES IV and the ECDH construction are taken verbatim from the
  open protocol spec; the provisioning channel's freshness comes from the
  host's per-command ephemeral P-256 keypair, not the IV.

## FAQ

### Which firmware release is this?

Token2 releases do not necessarily change every applet on the device. This
OTP applet has remained the same across the last several firmware releases —
it simply wasn't open source back then, so there is no earlier public
reference for it. The next planned modification of the OTP applet is in
**R3.4**, which adds password protection to OTP generation (tracked as a
self-created issue in this repository; the updated source code will be
published when R3.4 ships). Note that this protection is intended primarily
to address privacy concerns — TOTP profiles may contain user IDs and issuer
names — since OTP is always used together with an account password and, as
stated at the top of this document, is not phishing resistant either way.

### Is this 100% the same as the applet on my Token2 device?

For earlier releases of the hardware — yes, byte for byte. However, due to
ongoing difficulties sourcing larger quantities of NXP chips, we started
sourcing equivalent Java Card chips from alternative suppliers in order to
maintain production volumes. On those devices, there is roughly a 1% code
adjustment to adapt to minor differences in chip instructions and crypto
co-processor behavior. Since those alternative chips are not easily
available for DIY projects, the version published here is the one that works
with the NXP developer cards you can easily purchase (see
"Reproducing on an NXP card" above). Functionally and on the wire, all
variants behave identically — they implement the same protocol and pass the
same cross-validation checks against the CLI.

## File map

```
src/t2otp/Token2OtpApplet.java   the applet (single file)
build.xml                        ant-javacard build
cap/t2otp/javacard/t2otp.cap     prebuilt, verifier-clean CAP (JC 3.0.5 target)
test/cross_check.py              validation against the CLI's own code + RFC vectors
```
