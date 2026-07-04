#!/usr/bin/env python3
"""
Cross-validation harness for the Token2 OTP Java Card applet.

This does NOT reimplement the protocol independently. Instead it:
  1. Mirrors the applet's algorithms 1:1 in Python (same buffer logic,
     byte-wise u64/u16 division, manual ipad/opad HMAC, loop-based mod),
  2. Drives them with the *unmodified CLI code* from token2-otp-cli
     (token2/ecdh_enc.py, token2/data_structures.py, token2/__init__.py),
  3. Checks OTP outputs against the official RFC 4226 / RFC 6238 vectors.

If all assertions pass, the applet's crypto pipeline, wire formats and OTP
math are byte-compatible with the Python CLI and RFC-correct.
"""
import hashlib
import hmac as py_hmac
import struct
import sys

sys.path.insert(0, "/home/claude/cli")

from Crypto.Cipher import AES
from ecdsa import ECDH, NIST256p, SigningKey

# ---- the CLI's own, unmodified code -------------------------------------
from token2.ecdh_enc import encrypt_payload_ecdh, CIPHER_IV_1
from token2.data_structures import (
    WriteOTPEntry, DeleteOTPEntry, ReadOTPEntry, EnumOTPEntry,
    OTPType, OTPAlgorithm, OTPButtonFlag, EnumCodesSubCommand,
)

PASS = []


def check(name, cond):
    assert cond, f"FAIL: {name}"
    PASS.append(name)
    print(f"  ok  {name}")


# ==========================================================================
# 1:1 Python mirrors of the applet's routines
# ==========================================================================

def applet_div_u64_by_u16(ts8: bytes, divisor: int) -> bytes:
    """Mirror of Token2OtpApplet.divU64byU16 (byte-wise long division)."""
    d = divisor & 0xFFFF
    if d == 0:
        d = 30
    rem, out = 0, bytearray(8)
    for i in range(8):
        acc = (rem << 8) | ts8[i]
        out[i] = acc // d          # quotient digit < 256 because rem < d
        rem = acc % d
    return bytes(out)


def applet_hmac(alg_tag: int, key: bytes, msg: bytes) -> bytes:
    """Mirror of Token2OtpApplet.hmac (manual ipad/opad, 64-byte block)."""
    md = hashlib.sha256 if alg_tag == 0xC2 else hashlib.sha1
    assert len(key) <= 64          # protocol caps seeds at 64 bytes
    ipad = bytes((key[i] if i < len(key) else 0) ^ 0x36 for i in range(64))
    opad = bytes((key[i] if i < len(key) else 0) ^ 0x5C for i in range(64))
    inner = md(ipad + msg).digest()
    return md(opad + inner).digest()


def applet_otp_code(alg_tag: int, seed: bytes, moving_factor: bytes,
                    digits: int) -> str:
    """Mirror of Token2OtpApplet.emitOtp (dynamic truncation + loop mod)."""
    h = applet_hmac(alg_tag, seed, moving_factor)
    o = h[-1] & 0x0F
    binc = ((h[o] & 0x7F) << 24) | (h[o+1] << 16) | (h[o+2] << 8) | h[o+3]
    if digits >= 10:
        code = binc                       # binc < 2^31 < 10^10
    else:
        mod = 1
        for _ in range(digits):
            mod *= 10
        code = binc % mod
    return str(code).rjust(digits, "0")   # applet writes digits right-to-left


def applet_decrypt_write_blob(card_sk: SigningKey, blob: bytes) -> bytes:
    """Mirror of Token2OtpApplet.cmdWriteSeed's crypto path."""
    host_pub, ct = blob[:64], blob[64:]
    assert len(ct) >= 16 and len(ct) % 16 == 0
    ecdh = ECDH(curve=NIST256p, private_key=card_sk)
    ecdh.load_received_public_key_bytes(b"\x04" + host_pub, "uncompressed")
    shared_x = ecdh.generate_sharedsecret_bytes()      # == ALG_EC_SVDP_DH_PLAIN
    key = hashlib.sha256(shared_x).digest()            # == sha256.doFinal
    pt = AES.new(key, AES.MODE_CBC, IV=CIPHER_IV_1).decrypt(ct)
    pad = pt[-1]
    assert 1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad
    return pt[:-pad]


def applet_parse_entry(pt: bytes) -> dict:
    """Mirror of Token2OtpApplet.parseAndStoreEntry's field offsets."""
    e = {"type": pt[0], "alg": pt[1],
         "timestep": struct.unpack(">H", pt[2:4])[0],
         "code_len": pt[4], "btn": pt[5]}
    pos = 6
    al = pt[pos]; pos += 1
    e["app"] = pt[pos:pos+al]; pos += al
    cl = pt[pos]; pos += 1
    e["acct"] = pt[pos:pos+cl]; pos += cl
    sl = pt[pos]; pos += 1
    e["seed"] = pt[pos:pos+sl]; pos += sl
    assert pos == len(pt), "trailing bytes after entry"
    return e


def applet_emit_record(e: dict, with_code: bool, code: str) -> bytes:
    """Mirror of Token2OtpApplet.emitRecord wire output."""
    out = bytes([e["type"], e["alg"]]) + struct.pack(">H", e["timestep"])
    out += bytes([e["code_len"], e["btn"],
                  len(e["app"])]) + e["app"]
    out += bytes([len(e["acct"])]) + e["acct"]
    if with_code:
        out += bytes([len(code)]) + code.encode()
    return out


def extract_partial_flag(res):        # verbatim from token2/__init__.py
    is_partial = res[0] & 0x80 == 0x80
    return is_partial, bytes([res[0] & 0x7F]) + res[1:]


# ==========================================================================
# Test 1 — WRITE_SEED round trip: CLI encrypts, applet-logic decrypts
# ==========================================================================
print("[1] WRITE_SEED provisioning round trip (CLI encrypt -> applet decrypt)")
card_sk = SigningKey.generate(curve=NIST256p)
card_pub64 = card_sk.get_verifying_key().to_string("uncompressed")[1:]
check("card pubkey is 64 raw bytes (GET_ECDH_PUBKEY format)",
      len(card_pub64) == 64)

entry = WriteOTPEntry(
    type=OTPType.TOTP, algorithm=OTPAlgorithm.SHA1, timestep=30,
    code_length=6, btn_flag=OTPButtonFlag.BTN_NOT_REQUIRED,
    app_name=b"Test app", account_name=b"alice",
    seed=b"12345678901234567890")
entry.validate()

blob = encrypt_payload_ecdh(card_pub64, entry.serialize(), iv=CIPHER_IV_1)
pt = applet_decrypt_write_blob(card_sk, blob)
check("PKCS#7-unpadded plaintext == CLI cleartext", pt == entry.serialize())

parsed = applet_parse_entry(pt)
check("parsed fields match (type/alg/timestep/codeLen/btn/app/acct/seed)",
      parsed == {"type": 0x01, "alg": 0xC1, "timestep": 30, "code_len": 6,
                 "btn": 0x00, "app": b"Test app", "acct": b"alice",
                 "seed": b"12345678901234567890"})

# delete-entry cleartext (seed_len == 0, alg byte is 0x00!)
d = DeleteOTPEntry(app_name=b"Test app", account_name=b"alice")
d.validate()
dpt = applet_decrypt_write_blob(
    card_sk, encrypt_payload_ecdh(card_pub64, d.serialize(), iv=CIPHER_IV_1))
dparsed = applet_parse_entry(dpt)
check("delete blob parses with seed_len==0 before alg validation",
      dparsed["seed"] == b"" and dparsed["alg"] == 0x00)

# ==========================================================================
# Test 2 — TOTP counter division vs Python big-int division
# ==========================================================================
print("[2] u64/u16 byte-wise division (applet) vs native // (host)")
cases = [(59, 30), (1111111109, 30), (1111111111, 30), (1234567890, 30),
         (2000000000, 30), (20000000000, 30), (0, 30), (1, 1),
         (2**63 - 1, 65535), (2**64 - 1, 60), (123456789, 90)]
ok = all(applet_div_u64_by_u16(struct.pack(">Q", t), s)
         == struct.pack(">Q", t // s) for t, s in cases)
check(f"{len(cases)} division cases incl. 2^64-1 and timestep 65535", ok)

# ==========================================================================
# Test 3 — manual HMAC vs Python's hmac library
# ==========================================================================
print("[3] applet ipad/opad HMAC vs hmac library")
for tag, name in ((0xC1, "sha1"), (0xC2, "sha256")):
    ok = True
    for klen in (1, 20, 32, 63, 64):
        key = bytes(range(klen))
        msg = struct.pack(">Q", 0x0123456789ABCDEF)
        ok &= applet_hmac(tag, key, msg) == py_hmac.new(key, msg, name).digest()
    check(f"HMAC-{name.upper()} matches for key lengths 1..64", ok)

# ==========================================================================
# Test 4 — RFC 4226 Appendix D HOTP vectors (SHA-1, 6 digits)
# ==========================================================================
print("[4] RFC 4226 HOTP test vectors")
seed20 = b"12345678901234567890"
rfc4226 = ["755224", "287082", "359152", "969429", "338314",
           "254676", "287922", "162583", "399871", "520489"]
ok = all(applet_otp_code(0xC1, seed20, struct.pack(">Q", c), 6) == rfc4226[c]
         for c in range(10))
check("counters 0..9 produce the RFC 4226 codes", ok)

# ==========================================================================
# Test 5 — RFC 6238 Appendix B TOTP vectors (8 digits, step 30)
# ==========================================================================
print("[5] RFC 6238 TOTP test vectors (through the applet's division)")
seed32 = b"12345678901234567890123456789012"
vec_sha1 = {59: "94287082", 1111111109: "07081804", 1111111111: "14050471",
            1234567890: "89005924", 2000000000: "69279037",
            20000000000: "65353130"}
vec_sha256 = {59: "46119246", 1111111109: "68084774", 1111111111: "67062674",
              1234567890: "91819424", 2000000000: "90698825",
              20000000000: "77737706"}
ok1 = all(applet_otp_code(0xC1, seed20,
                          applet_div_u64_by_u16(struct.pack(">Q", t), 30), 8) == c
          for t, c in vec_sha1.items())
ok2 = all(applet_otp_code(0xC2, seed32,
                          applet_div_u64_by_u16(struct.pack(">Q", t), 30), 8) == c
          for t, c in vec_sha256.items())
check("SHA-1 vectors (incl. T past 2038)", ok1)
check("SHA-256 vectors", ok2)

# ==========================================================================
# Test 6 — READ_ONE / READ_ALL wire records parsed by the CLI's own parser
# ==========================================================================
print("[6] applet record emission vs CLI EnumOTPEntry.unserialize")
ts = 1111111109
code = applet_otp_code(0xC1, parsed["seed"],
                       applet_div_u64_by_u16(struct.pack(">Q", ts),
                                             parsed["timestep"]),
                       parsed["code_len"])

# READ_ONE response: full record with code (full_decode=True in the CLI)
rec = applet_emit_record(parsed, with_code=True, code=code)
one = list(EnumOTPEntry.unserialize(rec, full_decode=True))
check("READ_ONE record parses to exactly one entry", len(one) == 1)
e = one[0]
check("CLI-decoded entry fields match what was provisioned",
      (e.type, e.algorithm, e.timestep, e.code_length, e.btn_flag,
       e.app_name, e.account_name) ==
      (OTPType.TOTP, OTPAlgorithm.SHA1, 30, 6,
       OTPButtonFlag.BTN_NOT_REQUIRED, b"Test app", b"alice"))
check("CLI-decoded OTP code matches RFC-checked code", e.otp_code == code)

# READ_ALL page: TOTP(no btn) with code + HOTP entry masked (no tail),
# with the partial flag set on the first byte, like a multi-page response.
hotp_e = {"type": 0x00, "alg": 0xC2, "timestep": 0, "code_len": 8,
          "btn": 0x00, "app": b"Legacy VPN", "acct": b"bob",
          "seed": b"x" * 32}
page = bytearray(applet_emit_record(parsed, True, code)
                 + applet_emit_record(hotp_e, False, ""))
page[0] |= 0x80                       # applet sets partial bit on 1st byte
is_partial, stripped = extract_partial_flag(bytes(page))
check("CLI sees the partial flag and strips it", is_partial)
both = list(EnumOTPEntry.unserialize(stripped))
check("CLI parses the 2-entry page (default decode path)", len(both) == 2)
check("TOTP entry carries a code, HOTP entry is masked",
      both[0].otp_code == code and both[1].otp_code is None)

# READ_ONE request layout: CLI serialization vs applet's parse offsets
req = EnumCodesSubCommand.READ_ONE.value + ReadOTPEntry(
    timestamp=ts, app_name=b"Test app", account_name=b"alice").serialize()
check("READ_ONE request offsets (sub@0, ts@1..9, appLen@9)",
      req[0] == 0x01 and struct.unpack(">Q", req[1:9])[0] == ts
      and req[9] == 8 and req[10:18] == b"Test app"
      and req[18] == 5 and req[19:24] == b"alice")

# GET_INFO request/response framing
gi = b"\xD1\x10" + b"\x00" * 16
check("GET_INFO request is 18 bytes starting 0xD1 (applet's check)",
      len(gi) == 18 and gi[0] == 0xD1)
sn_resp = b"\xD1\x0A" + b"0BADC0FFEE"
import binascii
check("serial response decodes via CLI's unhexlify path",
      binascii.unhexlify(sn_resp[2:2 + sn_resp[1]]) == bytes.fromhex("0badc0ffee"))

print(f"\nALL {len(PASS)} CHECKS PASSED")
