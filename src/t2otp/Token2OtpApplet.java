/*
 * Token2OtpApplet — a Java Card implementation of the card side of the
 * Token2 OTP management protocol, so that a generic NXP JCOP smartcard
 * can be provisioned and read by the token2-otp-cli tool over PC/SC.
 *
 * Protocol reference:
 *   https://github.com/token2/token2-otp-cli/blob/main/docs/Token2-OTP-SDK-Protocol.md
 *
 * Implemented:
 *   - SELECT by AID F0 00 00 01 4F 74 70 01
 *   - GET_ECDH_PUBKEY        (80 C5 01 00)  -> 64-byte raw P-256 pubkey (X||Y)
 *   - WRITE_SEED             (80 C5 05 02)  -> ECDH + AES-256-CBC (IV-1) blob:
 *         write/overwrite entry, delete entry (empty seed), erase-all (empty data)
 *   - ENUM_CODES             (80 C5 05 00)  -> subcommands READ_ONE / GET_METADATA / READ_ALL
 *   - ENUM_CODES_CONTINUE    (80 C5 05 01)  -> pagination
 *   - READ_CONFIG            (80 C5 02 00)
 *   - ENABLE_TOTP            (80 C5 02 05)
 *   - SET_DEVICE_TYPE        (80 C5 02 01)  -> accepted as a no-op (nothing to disable on a card)
 *   - GET_INFO / serial      (80 33 00 00)  -> random 5-byte serial generated at install
 *
 * Deliberately NOT implemented (returns 6A86 "HID not supported", which the
 * CLI treats as an expected, model-specific condition):
 *   - WRITE_HOTP_SEED (80 C5 00 00) and the CFG_HOTP_* keystroke settings.
 *     A contactless/contact smartcard has no USB keyboard interface.
 *
 * Card requirements: Java Card 3.0.4+, ECC P-256 with
 * KeyAgreement.ALG_EC_SVDP_DH_PLAIN, AES-256, and 32-bit int support.
 * All recent NXP JCOP 3 / JCOP 4 parts (e.g. J3H145, J3R180) qualify.
 */
package t2otp;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.apdu.ExtendedLength;
import javacardx.crypto.Cipher;

public class Token2OtpApplet extends Applet implements ExtendedLength {

    /* ------------------------------------------------------------------ */
    /* Command bytes (see protocol doc §6)                                 */
    /* ------------------------------------------------------------------ */
    private static final byte CLA_PROPRIETARY   = (byte) 0x80;
    private static final byte INS_OTP          = (byte) 0xC5;
    private static final byte INS_GET_INFO     = (byte) 0x33;

    private static final byte P1_WRITE_HOTP_SEED = (byte) 0x00;
    private static final byte P1_GET_PUBKEY      = (byte) 0x01;
    private static final byte P1_CONFIG          = (byte) 0x02;
    private static final byte P1_ENUM            = (byte) 0x05;

    private static final byte P2_CFG_READ        = (byte) 0x00;
    private static final byte P2_CFG_DEVTYPE     = (byte) 0x01;
    private static final byte P2_CFG_HOTP_ENTER  = (byte) 0x02;
    private static final byte P2_CFG_HOTP_TOUCH  = (byte) 0x04;
    private static final byte P2_CFG_ENABLE_TOTP = (byte) 0x05;
    private static final byte P2_CFG_HOTP_KBD    = (byte) 0x06;

    private static final byte P2_ENUM_CMD        = (byte) 0x00;
    private static final byte P2_ENUM_CONTINUE   = (byte) 0x01;
    private static final byte P2_WRITE_SEED      = (byte) 0x02;
    /* R3.4 optional-PIN opcodes (OTP-on-FIDO manual V1.2, all under 80 C5 05 xx) */
    private static final byte P2_PIN_FLAG        = (byte) 0x04; // 1.12 Read OTP PIN Flag
    private static final byte P2_PIN_SET         = (byte) 0x05; // 1.13 Set OTP PIN
    private static final byte P2_PIN_VERIFY      = (byte) 0x06; // 1.14 Verify / 1.19 Lock
    private static final byte P2_PIN_CHANGE      = (byte) 0x08; // 1.15 Change OTP PIN
    private static final byte P2_PIN_AGREEMENT   = (byte) 0x09; // 1.17 Read Agreement PubKey

    private static final byte SUB_READ_ONE       = (byte) 0x01;
    private static final byte SUB_GET_METADATA   = (byte) 0x02;
    private static final byte SUB_READ_ALL       = (byte) 0x03;

    /* Protocol status words (§3.1) */
    private static final short SW_ENTRY_NOT_FOUND   = (short) 0x6A80;
    private static final short SW_NOT_ENOUGH_SPACE  = (short) 0x6A84;
    private static final short SW_HID_NOT_SUPPORTED = (short) 0x6A86;

    /* Entry field values */
    private static final byte TYPE_HOTP = (byte) 0x00;
    private static final byte TYPE_TOTP = (byte) 0x01;
    private static final byte ALG_SHA1_TAG   = (byte) 0xC1;
    private static final byte ALG_SHA256_TAG = (byte) 0xC2;

    /* ------------------------------------------------------------------ */
    /* Persistent entry store                                              */
    /* Record layout (210 bytes per slot):                                 */
    /*   used(1) type(1) alg(1) timestep(2,BE) codeLen(1) btn(1)           */
    /*   appLen(1) app(64) acctLen(1) acct(64) seedLen(1) seed(64)         */
    /*   hotpCounter(8,BE)                                                 */
    /* ------------------------------------------------------------------ */
    private static final short MAX_ENTRIES  = (short) 32;
    private static final short OFF_USED     = 0;
    private static final short OFF_TYPE     = 1;
    private static final short OFF_ALG      = 2;
    private static final short OFF_TSTEP    = 3;
    private static final short OFF_CODELEN  = 5;
    private static final short OFF_BTN      = 6;
    private static final short OFF_APPLEN   = 7;
    private static final short OFF_APP      = 8;
    private static final short OFF_ACCTLEN  = 72;
    private static final short OFF_ACCT     = 73;
    private static final short OFF_SEEDLEN  = 137;
    private static final short OFF_SEED     = 138;
    private static final short OFF_CTR      = 202;
    private static final short REC_SIZE     = 210;

    private static final short NAME_MAX = 64;
    private static final short SEED_MAX = 64;

    private final byte[] store;                 /* persistent EEPROM/flash   */
    private boolean totpEnabled = true;         /* §6.7 flag                 */
    private final byte[] serialHex;             /* 10 ASCII-hex chars (§6.10)*/

    /* ------------------------------------------------------------------ */
    /* Transient (RAM) buffers                                             */
    /* ------------------------------------------------------------------ */
    private static final short IN_SIZE    = 320;   /* biggest cmd: 64+208 blob */
    private static final short RESP_SIZE  = 672;
    private static final short PAGE_SOFT  = 500;   /* start a new page beyond  */
    private static final short REC_WIRE_MAX = 150; /* worst-case wire record   */

    private final byte[] inBuf;
    private final byte[] respBuf;
    private final byte[] pointBuf;   /* 65 bytes: 04 || X || Y */
    private final byte[] scratch;

    /* scratch layout */
    private static final short SC_PAD    = 0;    /* 64: HMAC ipad/opad        */
    private static final short SC_SHARED = 64;   /* 32: ECDH shared X / key   */
    private static final short SC_H1     = 96;   /* 32: hash slot 1 (final)   */
    private static final short SC_H2     = 128;  /* 32: hash slot 2 (inner)   */
    private static final short SC_CTR    = 160;  /* 8:  host timestamp        */
    private static final short SC_MF     = 168;  /* 8:  HOTP/TOTP moving factor */
    private static final short SC_SIZE   = 176;

    /* Enumeration cursor for READ_ALL pagination (transient).
     * enumState[0] == 0 means idle; otherwise it holds nextIndex + 1.
     * (Transient memory resets to zero on deselect, which must mean idle.) */
    private final short[] enumState;

    /* ------------------------------------------------------------------ */
    /* Crypto objects                                                      */
    /* ------------------------------------------------------------------ */
    private final KeyPair       ecKeyPair;
    private final byte[]        devPubW;      /* 65 bytes, 04||X||Y, persistent */
    private final KeyAgreement  ecdh;
    private final AESKey        aesKey;
    private final Cipher        aesCbc;
    private final MessageDigest sha1;
    private final MessageDigest sha256;

    /* R3.4 optional-PIN subsystem (see nested OtpPinManager) */
    private final OtpPinManager pin;

    /* AES-CBC IV-1 — a fixed constant defined by the open protocol (§7.2).
     * It is NOT a secret; freshness comes from the host's ephemeral keypair. */
    private static final byte[] IV_WRITE = {
        (byte) 0x9D, (byte) 0xD8, (byte) 0x91, (byte) 0x8E,
        (byte) 0x34, (byte) 0xF3, (byte) 0xCC, (byte) 0xAB,
        (byte) 0x08, (byte) 0xCB, (byte) 0x75, (byte) 0x18,
        (byte) 0xF7, (byte) 0x19, (byte) 0x38, (byte) 0xF1
    };

    /* NIST P-256 (secp256r1) domain parameters */
    private static final byte[] P256_P = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF };
    private static final byte[] P256_A = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFC };
    private static final byte[] P256_B = {
        (byte)0x5A,(byte)0xC6,(byte)0x35,(byte)0xD8,(byte)0xAA,(byte)0x3A,(byte)0x93,(byte)0xE7,
        (byte)0xB3,(byte)0xEB,(byte)0xBD,(byte)0x55,(byte)0x76,(byte)0x98,(byte)0x86,(byte)0xBC,
        (byte)0x65,(byte)0x1D,(byte)0x06,(byte)0xB0,(byte)0xCC,(byte)0x53,(byte)0xB0,(byte)0xF6,
        (byte)0x3B,(byte)0xCE,(byte)0x3C,(byte)0x3E,(byte)0x27,(byte)0xD2,(byte)0x60,(byte)0x4B };
    private static final byte[] P256_G = {
        (byte)0x04,
        (byte)0x6B,(byte)0x17,(byte)0xD1,(byte)0xF2,(byte)0xE1,(byte)0x2C,(byte)0x42,(byte)0x47,
        (byte)0xF8,(byte)0xBC,(byte)0xE6,(byte)0xE5,(byte)0x63,(byte)0xA4,(byte)0x40,(byte)0xF2,
        (byte)0x77,(byte)0x03,(byte)0x7D,(byte)0x81,(byte)0x2D,(byte)0xEB,(byte)0x33,(byte)0xA0,
        (byte)0xF4,(byte)0xA1,(byte)0x39,(byte)0x45,(byte)0xD8,(byte)0x98,(byte)0xC2,(byte)0x96,
        (byte)0x4F,(byte)0xE3,(byte)0x42,(byte)0xE2,(byte)0xFE,(byte)0x1A,(byte)0x7F,(byte)0x9B,
        (byte)0x8E,(byte)0xE7,(byte)0xEB,(byte)0x4A,(byte)0x7C,(byte)0x0F,(byte)0x9E,(byte)0x16,
        (byte)0x2B,(byte)0xCE,(byte)0x33,(byte)0x57,(byte)0x6B,(byte)0x31,(byte)0x5E,(byte)0xCE,
        (byte)0xCB,(byte)0xB6,(byte)0x40,(byte)0x68,(byte)0x37,(byte)0xBF,(byte)0x51,(byte)0xF5 };
    private static final byte[] P256_N = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xBC,(byte)0xE6,(byte)0xFA,(byte)0xAD,(byte)0xA7,(byte)0x17,(byte)0x9E,(byte)0x84,
        (byte)0xF3,(byte)0xB9,(byte)0xCA,(byte)0xC2,(byte)0xFC,(byte)0x63,(byte)0x25,(byte)0x51 };

    /* ------------------------------------------------------------------ */
    /* Lifecycle                                                           */
    /* ------------------------------------------------------------------ */

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new Token2OtpApplet(bArray, bOffset, bLength);
    }

    private Token2OtpApplet(byte[] bArray, short bOffset, byte bLength) {
        store = new byte[(short) (MAX_ENTRIES * REC_SIZE)];

        inBuf   = JCSystem.makeTransientByteArray(IN_SIZE,   JCSystem.CLEAR_ON_DESELECT);
        respBuf = JCSystem.makeTransientByteArray(RESP_SIZE, JCSystem.CLEAR_ON_DESELECT);
        pointBuf = JCSystem.makeTransientByteArray((short) 65, JCSystem.CLEAR_ON_DESELECT);
        scratch  = JCSystem.makeTransientByteArray(SC_SIZE,  JCSystem.CLEAR_ON_DESELECT);
        enumState = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_DESELECT);

        /* --- static device ECDH keypair (host side is ephemeral) --- */
        ecKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        setP256Params((ECPrivateKey) ecKeyPair.getPrivate());
        setP256Params((ECPublicKey) ecKeyPair.getPublic());
        ecKeyPair.genKeyPair();

        devPubW = new byte[65];
        ((ECPublicKey) ecKeyPair.getPublic()).getW(devPubW, (short) 0);

        ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);

        AESKey k;
        try {
            k = (AESKey) KeyBuilder.buildKey(
                    KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
                    KeyBuilder.LENGTH_AES_256, false);
        } catch (CryptoException e) {
            k = (AESKey) KeyBuilder.buildKey(
                    KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
        }
        aesKey = k;
        aesCbc = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);

        sha1   = MessageDigest.getInstance(MessageDigest.ALG_SHA,     false);
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

        /* --- random 5-byte serial, stored as 10 ASCII-hex chars --- */
        serialHex = new byte[10];
        RandomData rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        rng.generateData(scratch, SC_CTR, (short) 5);
        for (short i = 0; i < 5; i++) {
            serialHex[(short) (2 * i)]     = hexChar((byte) ((scratch[(short)(SC_CTR + i)] >> 4) & 0x0F));
            serialHex[(short) (2 * i + 1)] = hexChar((byte) (scratch[(short)(SC_CTR + i)] & 0x0F));
        }

        pin = new OtpPinManager();

        register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    private static void setP256Params(javacard.security.ECKey key) {
        key.setFieldFP(P256_P, (short) 0, (short) P256_P.length);
        key.setA(P256_A, (short) 0, (short) P256_A.length);
        key.setB(P256_B, (short) 0, (short) P256_B.length);
        key.setG(P256_G, (short) 0, (short) P256_G.length);
        key.setR(P256_N, (short) 0, (short) P256_N.length);
        key.setK((short) 1);
    }

    private static byte hexChar(byte nibble) {
        return (byte) (nibble < 10 ? ('0' + nibble) : ('A' + nibble - 10));
    }

    /* ------------------------------------------------------------------ */
    /* APDU dispatch                                                       */
    /* ------------------------------------------------------------------ */

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return; /* 9000 */
        }

        byte[] buf = apdu.getBuffer();
        byte cla = buf[ISO7816.OFFSET_CLA];
        byte ins = buf[ISO7816.OFFSET_INS];
        byte p1  = buf[ISO7816.OFFSET_P1];
        byte p2  = buf[ISO7816.OFFSET_P2];

        if ((byte) (cla & (byte) 0xFC) != CLA_PROPRIETARY) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        short inLen = receiveAll(apdu);

        if (ins == INS_GET_INFO) {
            cmdGetInfo(apdu, inLen);
            return;
        }
        if (ins != INS_OTP) {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

        switch (p1) {
            case P1_GET_PUBKEY:
                cmdGetPubkey(apdu);
                break;
            case P1_WRITE_HOTP_SEED:
                /* keystroke-HOTP: meaningless on a smartcard */
                ISOException.throwIt(SW_HID_NOT_SUPPORTED);
                break;
            case P1_CONFIG:
                cmdConfig(apdu, p2, inLen);
                break;
            case P1_ENUM:
                cmdEnumFamily(apdu, p2, inLen);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    /** Copy the full (possibly extended-length, possibly chunked) command
     *  data into inBuf. Returns the number of bytes received. */
    private short receiveAll(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short recv  = apdu.setIncomingAndReceive();
        short total = apdu.getIncomingLength();
        short cdata = apdu.getOffsetCdata();

        if (total > IN_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short read = 0;
        while (read < total) {
            Util.arrayCopyNonAtomic(buf, cdata, inBuf, read, recv);
            read += recv;
            if (read < total) {
                recv = apdu.receiveBytes(cdata);
            }
        }
        return total;
    }

    private void send(APDU apdu, byte[] src, short off, short len) {
        apdu.setOutgoing();
        apdu.setOutgoingLength(len);
        apdu.sendBytesLong(src, off, len);
    }

    /* ------------------------------------------------------------------ */
    /* GET_ECDH_PUBKEY (§6.3 step 1) — raw X||Y, no leading 0x04           */
    /* ------------------------------------------------------------------ */
    private void cmdGetPubkey(APDU apdu) {
        send(apdu, devPubW, (short) 1, (short) 64);
    }

    /* ------------------------------------------------------------------ */
    /* Config family: 80 C5 02 xx (§6.7–§6.9)                              */
    /* ------------------------------------------------------------------ */
    private void cmdConfig(APDU apdu, byte p2, short inLen) {
        switch (p2) {
            case P2_CFG_READ: {
                short n = (inLen >= 1) ? (short) (inBuf[0] & 0xFF) : (short) 10;
                if (n < 1)  n = 1;
                if (n > 64) n = 64;
                Util.arrayFillNonAtomic(respBuf, (short) 0, n, (byte) 0);
                /* byte 0: transfer type — FIDO(bit1) & keystroke(bit2) both
                 * "disabled": a smartcard has neither interface. */
                respBuf[0] = (byte) 0x03;
                /* byte 1: device config — HOTP supported (bit3) + NFC (bit5) */
                respBuf[1] = (byte) 0x14;
                /* bytes 2..5: appearance (custom), bytes 6..8: version 1.0.0 */
                if (n > 6) respBuf[6] = (byte) 0x01;
                /* byte 9: extension — TOTP supported (bit1, if enabled),
                 * CCID supported (bit5), HOTP-on-button NOT supported (bit6) */
                if (n > 9) {
                    respBuf[9] = (byte) (0x30 | (totpEnabled ? 0x01 : 0x00));
                }
                send(apdu, respBuf, (short) 0, n);
                break;
            }
            case P2_CFG_ENABLE_TOTP: {
                if (inLen != 1) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                totpEnabled = (inBuf[0] != (byte) 0x00);
                break; /* 9000, empty */
            }
            case P2_CFG_DEVTYPE:
                /* No USB composite interfaces exist on a card; accept and
                 * ignore. (This also removes the bricking foot-gun the
                 * protocol doc warns about.) */
                if (inLen != 1) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                break;
            case P2_CFG_HOTP_ENTER:
            case P2_CFG_HOTP_TOUCH:
            case P2_CFG_HOTP_KBD:
                ISOException.throwIt(SW_HID_NOT_SUPPORTED);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    /* ------------------------------------------------------------------ */
    /* Enumeration family: 80 C5 05 xx (§6.1, §6.2) + encrypted writes      */
    /* ------------------------------------------------------------------ */
    private void cmdEnumFamily(APDU apdu, byte p2, short inLen) {
        switch (p2) {
            case P2_ENUM_CMD: {
                if (inLen < 1) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                byte sub = inBuf[0];
                if (sub == SUB_READ_ALL) {
                    if (inLen < 9) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    /* R3.4: when a PIN is set, reads require an open verify window */
                    if (!pin.readsUnlocked(inBuf, (short) 1)) {
                        ISOException.throwIt(OtpPinManager.SW_COND_NOT_SAT);
                    }
                    Util.arrayCopyNonAtomic(inBuf, (short) 1, scratch, SC_CTR, (short) 8);
                    enumState[0] = 1; /* cursor = 0 */
                    sendEnumPage(apdu);
                } else if (sub == SUB_READ_ONE || sub == SUB_GET_METADATA) {
                    /* READ_ONE/METADATA carry the timestamp at inBuf[1..8] */
                    if (inLen >= 9 && !pin.readsUnlocked(inBuf, (short) 1)) {
                        ISOException.throwIt(OtpPinManager.SW_COND_NOT_SAT);
                    }
                    cmdReadOne(apdu, inLen, sub);
                } else {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
                break;
            }
            case P2_ENUM_CONTINUE: {
                if (inLen < 8) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                if (enumState[0] == 0) ISOException.throwIt(SW_ENTRY_NOT_FOUND);
                if (!pin.readsUnlocked(inBuf, (short) 0)) {
                    ISOException.throwIt(OtpPinManager.SW_COND_NOT_SAT);
                }
                Util.arrayCopyNonAtomic(inBuf, (short) 0, scratch, SC_CTR, (short) 8);
                sendEnumPage(apdu);
                break;
            }
            case P2_WRITE_SEED:
                cmdWriteSeed(apdu, inLen);
                break;
            case P2_PIN_AGREEMENT: {
                short n = pin.cmdReadAgreement(inBuf, (short) 0, inLen, respBuf);
                send(apdu, respBuf, (short) 0, n);
                break;
            }
            case P2_PIN_FLAG: {
                short n = pin.cmdReadFlag(respBuf);
                /* Per the protocol the flag response length follows the
                 * request Lc (04 -> status, 09 -> +PubVer/Crc, 29 -> +IV/EncRand
                 * challenge), capped at what we produced. Honour the caller's Lc. */
                short want = inLen;
                if (want <= 0 || want > n) want = n;
                send(apdu, respBuf, (short) 0, want);
                break;
            }
            case P2_PIN_SET:
                pin.cmdSetPin(inBuf, (short) 0, inLen);
                break;
            case P2_PIN_VERIFY: {
                /* P3 distinguishes Verify (xx) from Lock (01). The APDU P3 was
                 * the incoming Lc; the manual overloads P3=01,data=00 as LOCK. */
                byte p3 = apdu.getBuffer()[ISO7816.OFFSET_LC];
                pin.cmdVerifyOrLock(inBuf, (short) 0, inLen, p3, scratch, SC_CTR);
                break;
            }
            case P2_PIN_CHANGE:
                pin.cmdChangePin(inBuf, (short) 0, inLen);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    /* -------------------- READ_ALL with pagination --------------------- */
    /* On entry: scratch[SC_CTR..+8] holds the u64 host timestamp,          */
    /* enumState[0] holds the next slot index to visit.                     */
    private void sendEnumPage(APDU apdu) {
        short out = 0;
        short emitted = 0;
        short idx = (short) (enumState[0] - 1);
        short firstByteOff = -1;

        while (idx < MAX_ENTRIES) {
            short base = (short) (idx * REC_SIZE);
            if (store[(short) (base + OFF_USED)] == (byte) 0x01) {
                if (emitted > 0 && (short) (out + REC_WIRE_MAX) > PAGE_SOFT) {
                    break; /* next entry goes on the next page */
                }
                boolean withCode =
                        store[(short) (base + OFF_TYPE)] == TYPE_TOTP
                        && store[(short) (base + OFF_BTN)] == (byte) 0x00;
                if (emitted == 0) firstByteOff = out;
                out = emitRecord(base, withCode, false, out);
                emitted++;
            }
            idx++;
        }

        if (emitted == 0) {
            enumState[0] = 0;
            ISOException.throwIt(SW_ENTRY_NOT_FOUND); /* "empty token" (§3.1) */
        }

        /* any used entries left beyond idx? */
        boolean more = false;
        for (short j = idx; j < MAX_ENTRIES; j++) {
            if (store[(short) (j * REC_SIZE + OFF_USED)] == (byte) 0x01) {
                more = true;
                break;
            }
        }
        if (more) {
            respBuf[firstByteOff] |= (byte) 0x80; /* partial flag in type byte */
            enumState[0] = (short) (idx + 1);
        } else {
            enumState[0] = 0;
        }
        send(apdu, respBuf, (short) 0, out);
    }

    /* --------------------------- READ_ONE ------------------------------ */
    /* Request: 0x01 || ts(8) || appLen || app || acctLen || acct           */
    private void cmdReadOne(APDU apdu, short inLen, byte sub) {
        if (inLen < 11) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        Util.arrayCopyNonAtomic(inBuf, (short) 1, scratch, SC_CTR, (short) 8);

        short pos = 9;
        short appLen = (short) (inBuf[pos++] & 0xFF);
        if (appLen > NAME_MAX || (short) (pos + appLen + 1) > inLen) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        short appOff = pos;
        pos += appLen;
        short acctLen = (short) (inBuf[pos++] & 0xFF);
        if (acctLen < 1 || acctLen > NAME_MAX || (short) (pos + acctLen) > inLen) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        short acctOff = pos;

        short base = findEntry(appOff, appLen, acctOff, acctLen);
        if (base < 0) ISOException.throwIt(SW_ENTRY_NOT_FOUND);

        short out;
        if (sub == SUB_GET_METADATA) {
            /* code only: codeLen || ASCII digits */
            out = emitCode(base, (short) 0);
        } else {
            out = emitRecord(base, true, true, (short) 0);
        }
        send(apdu, respBuf, (short) 0, out);
    }

    /* ---------------------- encrypted write path ----------------------- */
    /* WRITE_SEED (§6.3–§6.5): empty data => erase-all; otherwise           */
    /* data = host_pub_XY(64) || AES-256-CBC(IV-1, PKCS7(cleartext))        */
    private void cmdWriteSeed(APDU apdu, short inLen) {
        if (inLen == 0) {
            eraseAll();
            return;
        }
        short ctLen = (short) (inLen - 64);
        if (ctLen < 16 || (short) (ctLen % 16) != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        /* ECDH: shared = X-coord of dev_priv * host_pub */
        pointBuf[0] = (byte) 0x04;
        Util.arrayCopyNonAtomic(inBuf, (short) 0, pointBuf, (short) 1, (short) 64);
        ecdh.init(ecKeyPair.getPrivate());
        short shLen;
        try {
            shLen = ecdh.generateSecret(pointBuf, (short) 0, (short) 65, scratch, SC_SHARED);
        } catch (CryptoException e) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            return;
        }

        /* session key = SHA-256(shared X) */
        sha256.reset();
        sha256.doFinal(scratch, SC_SHARED, shLen, scratch, SC_H1);
        aesKey.setKey(scratch, SC_H1);

        /* decrypt in place into respBuf (free at this point) */
        aesCbc.init(aesKey, Cipher.MODE_DECRYPT, IV_WRITE, (short) 0, (short) 16);
        short ptLen = aesCbc.doFinal(inBuf, (short) 64, ctLen, respBuf, (short) 0);

        /* PKCS#7 unpad */
        short pad = (short) (respBuf[(short) (ptLen - 1)] & 0xFF);
        if (pad < 1 || pad > 16 || pad > ptLen) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        for (short i = 1; i <= pad; i++) {
            if (respBuf[(short) (ptLen - i)] != (byte) pad) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
        }
        ptLen -= pad;

        parseAndStoreEntry(ptLen);
    }

    /* Cleartext (§6.3): type alg tstep(2) codeLen btn appLen app           */
    /*                   acctLen acct seedLen seed                          */
    private void parseAndStoreEntry(short ptLen) {
        if (ptLen < 9) ISOException.throwIt(ISO7816.SW_DATA_INVALID);

        byte  type    = respBuf[0];
        byte  alg     = respBuf[1];
        short tstep   = Util.getShort(respBuf, (short) 2);
        byte  codeLen = respBuf[4];
        byte  btn     = respBuf[5];

        short pos = 6;
        short appLen = (short) (respBuf[pos++] & 0xFF);
        if (appLen > NAME_MAX || (short) (pos + appLen + 1) > ptLen) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        short appOff = pos;
        pos += appLen;
        short acctLen = (short) (respBuf[pos++] & 0xFF);
        if (acctLen < 1 || acctLen > NAME_MAX || (short) (pos + acctLen + 1) > ptLen) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        short acctOff = pos;
        pos += acctLen;
        short seedLen = (short) (respBuf[pos++] & 0xFF);
        short seedOff = pos;
        if (seedLen > SEED_MAX || (short) (pos + seedLen) > ptLen) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        /* names/seed live in respBuf here — findEntry needs inBuf, so copy */
        Util.arrayCopyNonAtomic(respBuf, appOff,  inBuf, (short) 0,   appLen);
        Util.arrayCopyNonAtomic(respBuf, acctOff, inBuf, (short) 100, acctLen);
        short base = findEntry((short) 0, appLen, (short) 100, acctLen);

        if (seedLen == 0) {
            /* delete (§6.4) */
            if (base < 0) ISOException.throwIt(SW_ENTRY_NOT_FOUND);
            store[(short) (base + OFF_USED)] = (byte) 0x00;
            return;
        }

        /* validate a real write (§9) */
        if (type != TYPE_HOTP && type != TYPE_TOTP) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        if (alg != ALG_SHA1_TAG && alg != ALG_SHA256_TAG) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        short cd = (short) (codeLen & 0xFF);
        if (cd < 4 || cd > 10) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        if (type == TYPE_TOTP && tstep == 0) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        if (base < 0) {
            base = findFreeSlot();
            if (base < 0) ISOException.throwIt(SW_NOT_ENOUGH_SPACE);
        }

        JCSystem.beginTransaction();
        store[(short) (base + OFF_USED)]    = (byte) 0x01;
        store[(short) (base + OFF_TYPE)]    = type;
        store[(short) (base + OFF_ALG)]     = alg;
        Util.setShort(store, (short) (base + OFF_TSTEP), tstep);
        store[(short) (base + OFF_CODELEN)] = codeLen;
        store[(short) (base + OFF_BTN)]     = btn;
        store[(short) (base + OFF_APPLEN)]  = (byte) appLen;
        Util.arrayCopy(respBuf, appOff,  store, (short) (base + OFF_APP),  appLen);
        store[(short) (base + OFF_ACCTLEN)] = (byte) acctLen;
        Util.arrayCopy(respBuf, acctOff, store, (short) (base + OFF_ACCT), acctLen);
        store[(short) (base + OFF_SEEDLEN)] = (byte) seedLen;
        Util.arrayCopy(respBuf, seedOff, store, (short) (base + OFF_SEED), seedLen);
        Util.arrayFillNonAtomic(store, (short) (base + OFF_CTR), (short) 8, (byte) 0x00);
        JCSystem.commitTransaction();
    }

    private void eraseAll() {
        JCSystem.beginTransaction();
        for (short i = 0; i < MAX_ENTRIES; i++) {
            store[(short) (i * REC_SIZE + OFF_USED)] = (byte) 0x00;
        }
        JCSystem.commitTransaction();
    }

    /* ------------------------------------------------------------------ */
    /* Entry lookup helpers (names taken from inBuf)                        */
    /* ------------------------------------------------------------------ */
    private short findEntry(short appOff, short appLen, short acctOff, short acctLen) {
        for (short i = 0; i < MAX_ENTRIES; i++) {
            short base = (short) (i * REC_SIZE);
            if (store[(short) (base + OFF_USED)] != (byte) 0x01) continue;
            if ((store[(short) (base + OFF_APPLEN)]  & 0xFF) != appLen)  continue;
            if ((store[(short) (base + OFF_ACCTLEN)] & 0xFF) != acctLen) continue;
            if (appLen > 0 && Util.arrayCompare(inBuf, appOff, store,
                    (short) (base + OFF_APP), appLen) != 0) continue;
            if (Util.arrayCompare(inBuf, acctOff, store,
                    (short) (base + OFF_ACCT), acctLen) != 0) continue;
            return base;
        }
        return -1;
    }

    private short findFreeSlot() {
        for (short i = 0; i < MAX_ENTRIES; i++) {
            short base = (short) (i * REC_SIZE);
            if (store[(short) (base + OFF_USED)] != (byte) 0x01) return base;
        }
        return -1;
    }

    /* ------------------------------------------------------------------ */
    /* Wire-format record emission (§6.1)                                   */
    /* ------------------------------------------------------------------ */
    private short emitRecord(short base, boolean withCode, boolean bumpHotp, short out) {
        respBuf[out++] = store[(short) (base + OFF_TYPE)];
        respBuf[out++] = store[(short) (base + OFF_ALG)];
        respBuf[out++] = store[(short) (base + OFF_TSTEP)];
        respBuf[out++] = store[(short) (base + OFF_TSTEP + 1)];
        respBuf[out++] = store[(short) (base + OFF_CODELEN)];
        respBuf[out++] = store[(short) (base + OFF_BTN)];

        short appLen = (short) (store[(short) (base + OFF_APPLEN)] & 0xFF);
        respBuf[out++] = (byte) appLen;
        Util.arrayCopyNonAtomic(store, (short) (base + OFF_APP), respBuf, out, appLen);
        out += appLen;

        short acctLen = (short) (store[(short) (base + OFF_ACCTLEN)] & 0xFF);
        respBuf[out++] = (byte) acctLen;
        Util.arrayCopyNonAtomic(store, (short) (base + OFF_ACCT), respBuf, out, acctLen);
        out += acctLen;

        if (withCode) {
            out = emitOtp(base, bumpHotp, out);
        }
        return out;
    }

    /** codeLen byte + ASCII digits (used standalone by GET_METADATA). */
    private short emitCode(short base, short out) {
        return emitOtp(base, true, out);
    }

    private short emitOtp(short base, boolean bumpHotp, short out) {
        byte type = store[(short) (base + OFF_TYPE)];

        /* Build the 8-byte moving factor into scratch[SC_MF..] */
        if (type == TYPE_TOTP) {
            short tstep = Util.getShort(store, (short) (base + OFF_TSTEP));
            divU64byU16(scratch, SC_CTR, tstep, scratch, SC_MF);
        } else {
            Util.arrayCopyNonAtomic(store, (short) (base + OFF_CTR), scratch, SC_MF, (short) 8);
            if (bumpHotp) incrementCounter(base);
        }

        byte  alg     = store[(short) (base + OFF_ALG)];
        short seedLen = (short) (store[(short) (base + OFF_SEEDLEN)] & 0xFF);
        short hashLen = hmac(alg, store, (short) (base + OFF_SEED), seedLen,
                             scratch, SC_MF, (short) 8, scratch, SC_H1);

        /* RFC 4226 dynamic truncation */
        short o = (short) (scratch[(short) (SC_H1 + hashLen - 1)] & 0x0F);
        int bin = ((scratch[(short) (SC_H1 + o)]     & 0x7F) << 24)
                | ((scratch[(short) (SC_H1 + o + 1)] & 0xFF) << 16)
                | ((scratch[(short) (SC_H1 + o + 2)] & 0xFF) << 8)
                |  (scratch[(short) (SC_H1 + o + 3)] & 0xFF);

        short digits = (short) (store[(short) (base + OFF_CODELEN)] & 0xFF);
        int code;
        if (digits >= 10) {
            code = bin; /* bin < 2^31 < 10^10, so the value is its own residue */
        } else {
            int mod = 1;
            for (short i = 0; i < digits; i++) {
                mod *= 10;
            }
            code = bin % mod;
        }

        respBuf[out++] = (byte) digits;
        for (short i = (short) (digits - 1); i >= 0; i--) {
            respBuf[(short) (out + i)] = (byte) ('0' + (code % 10));
            code /= 10;
        }
        return (short) (out + digits);
    }

    private void incrementCounter(short base) {
        JCSystem.beginTransaction();
        for (short i = 7; i >= 0; i--) {
            short off = (short) (base + OFF_CTR + i);
            byte v = (byte) (store[off] + 1);
            store[off] = v;
            if (v != (byte) 0x00) break;
        }
        JCSystem.commitTransaction();
    }

    /* ------------------------------------------------------------------ */
    /* HMAC-SHA1 / HMAC-SHA256 (RFC 2104), key <= 64 bytes                  */
    /* ------------------------------------------------------------------ */
    private short hmac(byte algTag, byte[] key, short kOff, short kLen,
                       byte[] msg, short mOff, short mLen,
                       byte[] out, short outOff) {
        MessageDigest md = (algTag == ALG_SHA256_TAG) ? sha256 : sha1;
        short hLen = (algTag == ALG_SHA256_TAG) ? (short) 32 : (short) 20;

        for (short i = 0; i < 64; i++) {
            byte kb = (i < kLen) ? key[(short) (kOff + i)] : (byte) 0x00;
            scratch[(short) (SC_PAD + i)] = (byte) (kb ^ 0x36);
        }
        md.reset();
        md.update(scratch, SC_PAD, (short) 64);
        md.doFinal(msg, mOff, mLen, scratch, SC_H2); /* inner hash -> H2 */

        for (short i = 0; i < 64; i++) {
            byte kb = (i < kLen) ? key[(short) (kOff + i)] : (byte) 0x00;
            scratch[(short) (SC_PAD + i)] = (byte) (kb ^ 0x5C);
        }
        md.reset();
        md.update(scratch, SC_PAD, (short) 64);
        md.doFinal(scratch, SC_H2, hLen, out, outOff);
        return hLen;
    }

    /* 64-bit big-endian dividend / 16-bit divisor -> 64-bit BE quotient.   */
    /* Used for TOTP counter = timestamp / timestep. Requires int support.  */
    private static void divU64byU16(byte[] src, short srcOff, short divisor,
                                    byte[] dst, short dstOff) {
        int d = divisor & 0xFFFF;
        if (d == 0) d = 30;
        int rem = 0;
        for (short i = 0; i < 8; i++) {
            int acc = (rem << 8) | (src[(short) (srcOff + i)] & 0xFF);
            dst[(short) (dstOff + i)] = (byte) (acc / d);
            rem = acc % d;
        }
    }

    /* ------------------------------------------------------------------ */
    /* GET_INFO / serial number (§6.10): 80 33 00 00, 18-byte D1 request    */
    /* ------------------------------------------------------------------ */
    private void cmdGetInfo(APDU apdu, short inLen) {
        if (inLen != 18 || inBuf[0] != (byte) 0xD1) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        respBuf[0] = (byte) 0xD1;
        respBuf[1] = (byte) 0x0A; /* 10 ASCII-hex chars */
        Util.arrayCopyNonAtomic(serialHex, (short) 0, respBuf, (short) 2, (short) 10);
        send(apdu, respBuf, (short) 0, (short) 12);
    }

    static final class OtpPinManager {

        /* ---- status words (V1.2 semantics) ---- */
        static final short SW_OK               = (short) 0x9000;
        static final short SW_COND_NOT_SAT     = (short) 0x6985; // verify w/o PIN, or gated cmd
        static final short SW_SECURITY         = (short) 0x6982; // bad auth tag / wrong PIN
        static final short SW_PIN_LOCKED       = (short) 0x6983; // retry counter exhausted
        static final short SW_FUNC_NOT_SUP     = (short) 0x6A81; // Set when a PIN already exists
        static final short SW_WRONG_DATA       = (short) 0x6A80; // PIN rejected by policy

        /* ---- PIN policy (shared with PIN+; not lowerable over APDU) ---- */
        static final byte  PIN_ALG_AES256      = (byte) 0x07;
        static final short MIN_NUMERIC_LEN     = 6;
        static final short MIN_ALNUM_LEN       = 10;
        static final byte  DEFAULT_MAX_RETRY   = (byte) 100;

        /* Enforce the OTP-PIN complexity policy on the decrypted plaintext
         * (layout: alg(1) retry(1) len(1) pin...) per the manual (V1.2):
         * reject weak PINs with 6A80 rather than storing them. */
        private void enforcePinPolicy(byte[] p, short ptLen) {
            if (ptLen < 4) ISOException.throwIt(SW_WRONG_DATA);
            short plen  = (short) (p[2] & 0xFF);
            short pinOff = 3;
            if ((short) (pinOff + plen) > ptLen) ISOException.throwIt(SW_WRONG_DATA);

            boolean numeric = true;
            for (short i = 0; i < plen; i++) {
                byte c = p[(short) (pinOff + i)];
                if (c < '0' || c > '9') { numeric = false; break; }
            }

            if (numeric) {
                if (plen < MIN_NUMERIC_LEN) ISOException.throwIt(SW_WRONG_DATA);
                // all-identical digits
                boolean allSame = true;
                for (short i = 1; i < plen; i++) {
                    if (p[(short)(pinOff+i)] != p[pinOff]) { allSame = false; break; }
                }
                if (allSame) ISOException.throwIt(SW_WRONG_DATA);
                // strictly ascending / descending consecutive sequence
                boolean asc = true, desc = true;
                for (short i = 1; i < plen; i++) {
                    short d = (short) (p[(short)(pinOff+i)] - p[(short)(pinOff+i-1)]);
                    if (d != 1)  asc  = false;
                    if (d != -1) desc = false;
                }
                if (asc || desc) ISOException.throwIt(SW_WRONG_DATA);
                // palindrome / mirror
                boolean palin = true;
                for (short i = 0; i < (short)(plen/2); i++) {
                    if (p[(short)(pinOff+i)] != p[(short)(pinOff+plen-1-i)]) { palin = false; break; }
                }
                if (palin) ISOException.throwIt(SW_WRONG_DATA);
                // no single digit appears more than 3 times
                for (byte d = '0'; d <= '9'; d++) {
                    short cnt = 0;
                    for (short i = 0; i < plen; i++) {
                        if (p[(short)(pinOff+i)] == d) cnt++;
                    }
                    if (cnt > 3) ISOException.throwIt(SW_WRONG_DATA);
                }
            } else {
                if (plen < MIN_ALNUM_LEN) ISOException.throwIt(SW_WRONG_DATA);
                // at least two of: upper, lower, digit, special
                boolean up=false, lo=false, di=false, sp=false;
                for (short i = 0; i < plen; i++) {
                    byte c = p[(short)(pinOff+i)];
                    if (c >= 'A' && c <= 'Z') up = true;
                    else if (c >= 'a' && c <= 'z') lo = true;
                    else if (c >= '0' && c <= '9') di = true;
                    else sp = true;
                }
                short cats = 0;
                if (up) cats++; if (lo) cats++; if (di) cats++; if (sp) cats++;
                if (cats < 2) ISOException.throwIt(SW_WRONG_DATA);
            }
        }

        /* 5-minute verified window; the card has no clock, so it is driven off
         * the host UNIX timestamp supplied with each ENUM read (same source the
         * TOTP counter already trusts). 0 => no active window. */
        static final short WINDOW_SECONDS      = 300;

        /* ---- persistent PIN state ---- */
        private final byte[] pinHash;      // 32: SHA-256(PIN); zeroed when unset
        private boolean      pinSet;
        private byte         pinLen;       // stated length of the PIN
        private boolean      pinNumeric;   // for the min-length rule on set/change
        private byte         retryLeft;
        private byte         maxRetry;
        private boolean      locked;

        /* ---- session (transient) ---- */
        private final AESKey       sessEnc;      // SessionEncKey
        private final byte[]       sessMac;      // 32: SessionMacKey
        private final byte[]       rand;         // 16: current challenge (single-use)
        private final short[]      flags;        // [0]=sessionValid [1]=rand valid
        private final byte[]       windowStart;  // 8: host ts at last successful verify
        private final short[]      windowState;  // [0]=1 if window open

        /* ---- crypto engines ---- */
        private final KeyPair       ecdhKp;      // ephemeral P-256 agreement key
        private final byte[]        devAgreeW;   // 65: 04||X||Y of ecdhKp public
        private final KeyAgreement  ecdh;
        private final KeyPair       ec521Kp;     // device ECC-521 signing key (SAMPLE)
        private final Signature     sig521;      // ALG_ECDSA_SHA_512
        private final Cipher        aes;
        private final MessageDigest sha256;
        private final MessageDigest sha512;
        private final RandomData    rng;
        private final AESKey        tmpAes;      // for keying with arbitrary 32B values

        /* scratch */
        private final byte[] sc;   // 200 bytes
        private static final short SC_SHARED = 0;    // 32
        private static final short SC_PRK    = 32;   // 32
        private static final short SC_INFO   = 64;   // 32
        private static final short SC_PAD    = 96;   // 64 (HMAC)
        private static final short SC_H      = 160;  // 32
        private static final short SC_SIZE   = 200;

        private final byte[] pt;   // 64: decrypted PIN-command plaintext

        /* HKDF info strings: "TOTP HMAC key"||01 and "TOTP AES key"||01 */
        private static final byte[] INFO_MAC = {
            (byte)'T',(byte)'O',(byte)'T',(byte)'P',(byte)' ',(byte)'H',(byte)'M',
            (byte)'A',(byte)'C',(byte)' ',(byte)'k',(byte)'e',(byte)'y',(byte)0x01 };
        private static final byte[] INFO_ENC = {
            (byte)'T',(byte)'O',(byte)'T',(byte)'P',(byte)' ',(byte)'A',(byte)'E',
            (byte)'S',(byte)' ',(byte)'k',(byte)'e',(byte)'y',(byte)0x01 };

        /* PubVer reported in the Flag response (host uses it to pick the pubkey) */
        private static final short PUB_VER = (short) 0x0001;

        /* ===== SAMPLE ECC-521 device signing key — REPLACE PER DEVICE/BATCH ===== */
        private static final byte[] SAMPLE_DEV_PRIV_D = {
            (byte)0x01,(byte)0xB6,(byte)0x06,(byte)0x97,(byte)0xD5,(byte)0xC4,(byte)0xB3,(byte)0x58,
            (byte)0x51,(byte)0x86,(byte)0xDC,(byte)0xC8,(byte)0x34,(byte)0x68,(byte)0x85,(byte)0x4D,
            (byte)0xEE,(byte)0x52,(byte)0x6D,(byte)0x7C,(byte)0x2D,(byte)0x0F,(byte)0x5A,(byte)0x9B,
            (byte)0xE4,(byte)0x4D,(byte)0x05,(byte)0xD5,(byte)0x91,(byte)0xAE,(byte)0x4A,(byte)0x6A,
            (byte)0xC3,(byte)0x59,(byte)0xCA,(byte)0xC7,(byte)0x7A,(byte)0xEF,(byte)0xEB,(byte)0xC3,
            (byte)0xBD,(byte)0xBB,(byte)0x47,(byte)0x41,(byte)0x71,(byte)0xAF,(byte)0xC0,(byte)0xBC,
            (byte)0xE6,(byte)0x90,(byte)0xD2,(byte)0x2E,(byte)0xB1,(byte)0x49,(byte)0x75,(byte)0x20,
            (byte)0xD0,(byte)0x7D,(byte)0xB5,(byte)0x85,(byte)0x1F,(byte)0x1F,(byte)0xFF,(byte)0x3A,
            (byte)0x98,(byte)0x45
        };
        private static final byte[] SAMPLE_DEV_PUB_X = {
            (byte)0x01,(byte)0x0D,(byte)0x09,(byte)0xA6,(byte)0x4D,(byte)0xAD,(byte)0xB7,(byte)0x2C,
            (byte)0x1E,(byte)0x0D,(byte)0x2C,(byte)0x04,(byte)0x72,(byte)0xBE,(byte)0x87,(byte)0x83,
            (byte)0xED,(byte)0x03,(byte)0x78,(byte)0x78,(byte)0xE0,(byte)0x67,(byte)0xD6,(byte)0x8B,
            (byte)0xB8,(byte)0xB3,(byte)0xF0,(byte)0x93,(byte)0x66,(byte)0x12,(byte)0xE1,(byte)0x8B,
            (byte)0x5B,(byte)0xE5,(byte)0x65,(byte)0xD0,(byte)0x9F,(byte)0x6B,(byte)0x6F,(byte)0x29,
            (byte)0x00,(byte)0x53,(byte)0x97,(byte)0xE0,(byte)0x44,(byte)0x15,(byte)0xE9,(byte)0x5E,
            (byte)0x02,(byte)0xB8,(byte)0x1E,(byte)0x02,(byte)0x97,(byte)0x97,(byte)0x30,(byte)0x2F,
            (byte)0xF0,(byte)0x4B,(byte)0xBA,(byte)0x10,(byte)0xAB,(byte)0x12,(byte)0x2B,(byte)0xF9,
            (byte)0x8A,(byte)0x6F
        };
        private static final byte[] SAMPLE_DEV_PUB_Y = {
            (byte)0x00,(byte)0xEF,(byte)0x2B,(byte)0xA9,(byte)0xAB,(byte)0x06,(byte)0x83,(byte)0x82,
            (byte)0x3D,(byte)0x88,(byte)0xAB,(byte)0xE2,(byte)0x50,(byte)0xF6,(byte)0x06,(byte)0x9B,
            (byte)0xBA,(byte)0x17,(byte)0x21,(byte)0x1B,(byte)0xF4,(byte)0xE8,(byte)0xA4,(byte)0x11,
            (byte)0x32,(byte)0x3A,(byte)0xD1,(byte)0xE0,(byte)0xCB,(byte)0x25,(byte)0x97,(byte)0x65,
            (byte)0xD7,(byte)0xA7,(byte)0xDC,(byte)0xCF,(byte)0xE0,(byte)0x4F,(byte)0xC7,(byte)0xF3,
            (byte)0x85,(byte)0x78,(byte)0x55,(byte)0xA7,(byte)0xFC,(byte)0x5E,(byte)0x84,(byte)0xBA,
            (byte)0x6E,(byte)0x81,(byte)0x46,(byte)0xF3,(byte)0xA9,(byte)0x60,(byte)0x1E,(byte)0x15,
            (byte)0x88,(byte)0x70,(byte)0x8B,(byte)0x79,(byte)0xE7,(byte)0xDE,(byte)0x23,(byte)0x43,
            (byte)0xBF,(byte)0x4E
        };

        /* secp521r1 domain parameters (uncompressed G = 04||X||Y) */

        OtpPinManager() {
            pinHash     = new byte[32];
            sessMac     = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
            rand        = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
            flags       = JCSystem.makeTransientShortArray((short) 2, JCSystem.CLEAR_ON_DESELECT);
            windowStart = JCSystem.makeTransientByteArray((short) 8, JCSystem.CLEAR_ON_DESELECT);
            windowState = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
            sc          = JCSystem.makeTransientByteArray(SC_SIZE, JCSystem.CLEAR_ON_DESELECT);
            pt          = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);

            maxRetry  = DEFAULT_MAX_RETRY;
            retryLeft = DEFAULT_MAX_RETRY;

            ecdhKp = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
            P256.set((ECPrivateKey) ecdhKp.getPrivate());
            P256.set((ECPublicKey) ecdhKp.getPublic());
            ecdh   = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
            devAgreeW = new byte[65];

            ec521Kp = new KeyPair(KeyPair.ALG_EC_FP, (short) 521);
            set521((ECPrivateKey) ec521Kp.getPrivate(), true);
            set521((ECPublicKey)  ec521Kp.getPublic(),  false);
            sig521 = Signature.getInstance(Signature.ALG_ECDSA_SHA_512, false);

            aes    = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
            sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
            sha512 = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);
            rng    = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

            sessEnc = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
                                                   KeyBuilder.LENGTH_AES_256, false);
            tmpAes  = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
                                                   KeyBuilder.LENGTH_AES_256, false);
        }

        boolean isPinSet()    { return pinSet; }
        boolean isLocked()    { return locked; }

        /* Whether OTP reads are permitted right now: no PIN set, OR an open window.
         * hostTs is the 8-byte UNIX timestamp the ENUM command already carries. */
        boolean readsUnlocked(byte[] hostTs, short off) {
            if (!pinSet) return true;
            if (windowState[0] == 0) return false;
            // open if (hostTs - windowStart) < WINDOW_SECONDS, using unsigned compare
            return withinWindow(hostTs, off);
        }

        /* --- 1.17 Read Agreement PubKey: 80 C5 05 09, data = hostPub(64) --- */
        short cmdReadAgreement(byte[] in, short inOff, short inLen, byte[] out) {
            if (inLen != 64) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

            // regenerate our ephemeral agreement key each handshake
            ecdhKp.genKeyPair();
            ((ECPublicKey) ecdhKp.getPublic()).getW(devAgreeW, (short) 0);
            // response starts with the 64-byte raw device agreement pubkey
            Util.arrayCopyNonAtomic(devAgreeW, (short) 1, out, (short) 0, (short) 64);

            // DevSign = ECDSA-P521-SHA512 over (hostPub64 || devPub64)
            Util.arrayCopyNonAtomic(in, inOff, sc, (short) 0, (short) 64);
            Util.arrayCopyNonAtomic(out, (short) 0, sc, (short) 64, (short) 64);
            sig521.init(ec521Kp.getPrivate(), Signature.MODE_SIGN);
            short sigLen = sig521.sign(sc, (short) 0, (short) 128, out, (short) 64);

            // derive the session immediately so subsequent PIN cmds can use it
            deriveSession(in, inOff);
            return (short) (64 + sigLen);
        }

        /* --- 1.12 Read OTP PIN Flag: 80 C5 05 04 --- */
        short cmdReadFlag(byte[] out) {
            out[0] = pinSet ? PIN_ALG_AES256 : 0x00;
            out[1] = pinSet ? retryLeft : 0x00;
            out[2] = pinSet ? pinLen : 0x00;
            out[3] = maxRetry;
            out[4] = 0x00; // FpEnable: no fingerprint on a plain card
            Util.setShort(out, (short) 5, PUB_VER);
            Util.setShort(out, (short) 7, crc16l());
            // IV(16) + EncRand(16): fresh single-use challenge, delivered encrypted
            if (flags[0]==0) { // no session -> cannot encrypt a challenge
                // still return a well-formed structure with zero IV/EncRand
                Util.arrayFillNonAtomic(out, (short) 9, (short) 32, (byte) 0);
                return 41;
            }
            rng.generateData(out, (short) 9, (short) 16);       // IV
            rng.generateData(rand, (short) 0, (short) 16);      // Rand (kept on card)
            flags[1] = 1;                                        // rand valid
            sessEnc.setKey(scGetEncKey(), (short) 0);
            aes.init(sessEnc, Cipher.MODE_ENCRYPT, out, (short) 9, (short) 16);
            aes.doFinal(rand, (short) 0, (short) 16, out, (short) 25);
            return 41;
        }

        /* --- 1.13 Set OTP PIN: 80 C5 05 05, data = IV|NewPinEnc|NewPinAuth[16] --- */
        void cmdSetPin(byte[] in, short off, short len) {
            // Set only works from the unprotected state. If a PIN already exists
            // the device reports 6A81 (function not supported in this state).
            if (pinSet) ISOException.throwIt(SW_FUNC_NOT_SUP);
            short ptLen = openPinBlob(in, off, len, /*hasOldHash*/ false);
            // Enforce the OTP-PIN policy on the decrypted PIN; reject weak PINs
            // with 6A80 per the manual (V1.2).
            enforcePinPolicy(pt, ptLen);
            storeNewPin(ptLen);
        }

        /* --- 1.15 Change OTP PIN: 80 C5 05 08 --- */
        void cmdChangePin(byte[] in, short off, short len) {
            if (!pinSet) ISOException.throwIt(SW_COND_NOT_SAT);
            if (locked)  ISOException.throwIt(SW_PIN_LOCKED);
            short ptLen = openPinBlob(in, off, len, /*hasOldHash*/ true);
            // openPinBlob verified the old-PIN hash already. A change to a
            // zero-length PIN is a *remove* and skips the complexity policy;
            // otherwise the new PIN must satisfy it.
            short newLen = (short) (pt[2] & 0xFF);
            if (newLen > 0) enforcePinPolicy(pt, ptLen);
            storeNewPin(ptLen);
        }

        /* --- 1.14 Verify / 1.19 Lock: 80 C5 05 06 --- */
        void cmdVerifyOrLock(byte[] in, short off, short len, byte p3,
                             byte[] hostTs, short tsOff) {
            if (p3 == (byte) 0x01) {            // 1.19 LOCK: data = 00
                windowState[0] = 0;
                flags[1] = 0;
                return;
            }
            if (!pinSet) ISOException.throwIt(SW_COND_NOT_SAT);
            if (locked)  ISOException.throwIt(SW_PIN_LOCKED);
            if (flags[0]==0 || flags[1] == 0) ISOException.throwIt(SW_COND_NOT_SAT);

            // data = IV(16) | PinHashEnc2 : peel SessionEncKey, then the PIN layer
            if (len < 32) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            sessEnc.setKey(scGetEncKey(), (short) 0);
            aes.init(sessEnc, Cipher.MODE_DECRYPT, in, off, (short) 16);
            short n = aes.doFinal(in, (short) (off + 16), (short) (len - 16), sc, SC_H);
            // sc[SC_H..] = PinHashEnc = AES(PinHash; SHA256(Rand)[0:16]; Rand)
            // verify by recomputing with the stored PIN hash
            sha256.reset();
            sha256.doFinal(rand, (short) 0, (short) 16, sc, SC_INFO);   // IV2 = SHA256(Rand)
            tmpAes.setKey(pinHash, (short) 0);
            aes.init(tmpAes, Cipher.MODE_ENCRYPT, sc, SC_INFO, (short) 16);
            aes.doFinal(rand, (short) 0, (short) 16, sc, SC_SHARED);    // expected PinHashEnc

            flags[1] = 0;                       // Rand is single-use, spend it now
            if (n < 16 || Util.arrayCompare(sc, SC_H, sc, SC_SHARED, (short) 16) != 0) {
                failVerify();
                ISOException.throwIt(SW_SECURITY);
            }
            // success: reset retry, open the 5-minute window
            retryLeft = maxRetry;
            Util.arrayCopyNonAtomic(hostTs, tsOff, windowStart, (short) 0, (short) 8);
            windowState[0] = 1;
        }

        /* Provide the SessionEncKey/SessionMacKey to the seed-write & enum paths so
         * they can wrap OTP data once a PIN is set. Returns false if no session. */
        boolean sessionReady() { return flags[0]!=0; }

        void encWrap(byte[] iv, short ivOff, byte[] pt, short ptOff, short ptLen,
                     byte[] out, short outOff) {
            sessEnc.setKey(scGetEncKey(), (short) 0);
            aes.init(sessEnc, Cipher.MODE_ENCRYPT, iv, ivOff, (short) 16);
            aes.doFinal(pt, ptOff, ptLen, out, outOff);
        }
        short decWrap(byte[] iv, short ivOff, byte[] ct, short ctOff, short ctLen,
                      byte[] out, short outOff) {
            sessEnc.setKey(scGetEncKey(), (short) 0);
            aes.init(sessEnc, Cipher.MODE_DECRYPT, iv, ivOff, (short) 16);
            return aes.doFinal(ct, ctOff, ctLen, out, outOff);
        }
        void mac(byte[] data, short off, short len, byte[] out, short outOff) {
            hmacSha256(sessMac, (short) 0, (short) 32, data, off, len, out, outOff);
        }

        /* ================= internals ================= */

        private byte[] scGetEncKey() {
            // SessionEncKey is stored in sc[SC_PRK+? ] region persistently within a
            // session; we keep it in a dedicated 32-byte area re-derived at handshake.
            return sessKeyBuf;
        }
        private final byte[] sessKeyBuf =
            JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);

        private void deriveSession(byte[] hostPub, short off) {
            pt[0] = (byte) 0x04;
            Util.arrayCopyNonAtomic(hostPub, off, pt, (short) 1, (short) 64);
            ecdh.init(ecdhKp.getPrivate());
            short shl = ecdh.generateSecret(pt, (short) 0, (short) 65, sc, SC_SHARED);
            // pu1Key = shared[0:32]; salt = 32 zero bytes
            Util.arrayFillNonAtomic(sc, SC_PAD, (short) 32, (byte) 0);
            hmacSha256(sc, SC_PAD, (short) 32, sc, SC_SHARED, (short) 32, sc, SC_PRK); // pu1PRKey
            // SessionMacKey = HMAC(pu1PRKey; INFO_MAC)
            hmacSha256(sc, SC_PRK, (short) 32, INFO_MAC, (short) 0, (short) INFO_MAC.length,
                       sessMac, (short) 0);
            // SessionEncKey = HMAC(pu1PRKey; INFO_ENC)
            hmacSha256(sc, SC_PRK, (short) 32, INFO_ENC, (short) 0, (short) INFO_ENC.length,
                       sessKeyBuf, (short) 0);
            flags[0] = 1;
        }

        /* Decrypt and authenticate a Set/Change PIN blob.
         * layout: IV(16) | NewPinEnc(16) | NewPinAuth[0,16] [ | OldPinHashEnc(16) ]
         * returns the plaintext length placed in pt[] (the PKCS#5-unpadded NewPin) */
        private short openPinBlob(byte[] in, short off, short len, boolean hasOldHash) {
            if (flags[0]==0) ISOException.throwIt(SW_COND_NOT_SAT);
            short need = hasOldHash ? (short) 64 : (short) 48;
            if (len < need) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

            short ivOff  = off;
            short encOff = (short) (off + 16);
            short authOff= (short) (off + 32);
            short oldOff = (short) (off + 48);

            // verify NewPinAuth = HMAC(SessionMacKey; NewPinEnc [|| OldPinHashEnc])
            short macLen = hasOldHash ? (short) 32 : (short) 16;
            Util.arrayCopyNonAtomic(in, encOff, sc, SC_H, (short) 16);
            if (hasOldHash) Util.arrayCopyNonAtomic(in, oldOff, sc, (short) (SC_H + 16), (short) 16);
            hmacSha256(sessMac, (short) 0, (short) 32, sc, SC_H, macLen, sc, SC_SHARED);
            if (Util.arrayCompare(sc, SC_SHARED, in, authOff, (short) 16) != 0) {
                ISOException.throwIt(SW_SECURITY);
            }

            if (hasOldHash) {
                // OldPinHashEnc = AES(SessionEncKey; IV; SHA256(oldPin)[0:16]); check it
                sessEnc.setKey(sessKeyBuf, (short) 0);
                aes.init(sessEnc, Cipher.MODE_DECRYPT, in, ivOff, (short) 16);
                aes.doFinal(in, oldOff, (short) 16, sc, SC_INFO);
                if (Util.arrayCompare(sc, SC_INFO, pinHash, (short) 0, (short) 16) != 0) {
                    failVerify();
                    ISOException.throwIt(SW_SECURITY);
                }
            }

            // decrypt NewPinEnc -> pt (PinAlgId|PinRetry|OtpPinLen|OtpPin, PKCS#5)
            sessEnc.setKey(sessKeyBuf, (short) 0);
            aes.init(sessEnc, Cipher.MODE_DECRYPT, in, ivOff, (short) 16);
            short n = aes.doFinal(in, encOff, (short) 16, pt, (short) 0);
            short pad = (short) (pt[(short) (n - 1)] & 0xFF);
            if (pad < 1 || pad > 16 || pad > n) ISOException.throwIt(SW_WRONG_DATA);
            return (short) (n - pad);
        }

        /* pt[0..ptLen) = PinAlgId(1)|PinRetry(1)|OtpPinLen(1)|OtpPin(...) */
        private void storeNewPin(short ptLen) {
            if (ptLen < 4) ISOException.throwIt(SW_WRONG_DATA);
            byte alg    = pt[0];
            byte retry  = pt[1];
            short plen  = (short) (pt[2] & 0xFF);
            short pinOff= 3;
            if (alg != PIN_ALG_AES256) ISOException.throwIt(SW_WRONG_DATA);
            if ((short) (pinOff + plen) > ptLen) ISOException.throwIt(SW_WRONG_DATA);

            // A zero-length new PIN means REMOVE: clear all PIN state and return
            // the device to the unprotected state (OtpPinLen == 0, AlgId == 0).
            if (plen == 0) {
                JCSystem.beginTransaction();
                Util.arrayFillNonAtomic(pinHash, (short) 0, (short) 32, (byte) 0);
                pinLen    = 0;
                retryLeft = maxRetry;
                locked    = false;
                pinSet    = false;
                windowState[0] = 0;   // close any open read window
                JCSystem.commitTransaction();
                return;
            }

            boolean numeric = true;
            for (short i = 0; i < plen; i++) {
                byte c = pt[(short) (pinOff + i)];
                if (c < '0' || c > '9') { numeric = false; break; }
            }
            short min = numeric ? MIN_NUMERIC_LEN : MIN_ALNUM_LEN;
            if (plen < min) ISOException.throwIt(SW_WRONG_DATA);   // policy, not lowerable

            sha256.reset();
            sha256.doFinal(pt, pinOff, plen, sc, SC_H);

            JCSystem.beginTransaction();
            Util.arrayCopy(sc, SC_H, pinHash, (short) 0, (short) 32);
            pinLen     = (byte) plen;
            pinNumeric = numeric;
            maxRetry   = (retry == 0) ? DEFAULT_MAX_RETRY : retry;
            retryLeft  = maxRetry;
            locked     = false;
            pinSet     = true;
            JCSystem.commitTransaction();
        }

        void deletePinIfRequested(byte[] in, short off, short len) {
            // Change with OtpPinLen==0 removes the PIN. Detected after decrypt:
            // handled inside storeNewPin path when plen==0 would fail min-length,
            // so deletion uses a distinct plaintext len of 3 (no PIN bytes).
        }

        private void failVerify() {
            JCSystem.beginTransaction();
            if (retryLeft > 0) retryLeft--;
            if (retryLeft == 0) locked = true;
            JCSystem.commitTransaction();
        }

        /* unsigned (hostTs - windowStart) < WINDOW_SECONDS on 8-byte BE values.
         * Java Card has no long, so compute the difference byte-wise. */
        private boolean withinWindow(byte[] ts, short off) {
            if (ucmp(ts, off, windowStart, (short) 0) < 0) return false; // clock went back
            short borrow = 0;
            for (short i = 7; i >= 0; i--) {
                short a = (short) (ts[(short) (off + i)] & 0xFF);
                short b = (short) (windowStart[i] & 0xFF);
                short d = (short) (a - b - borrow);
                if (d < 0) { d = (short) (d + 256); borrow = 1; } else { borrow = 0; }
                sc[(short) (SC_H + i)] = (byte) d;
            }
            // any of the top 6 difference bytes set => >= 2^16 s => window closed
            for (short i = 0; i < 6; i++) {
                if (sc[(short) (SC_H + i)] != 0) return false;
            }
            short hi = (short) (sc[(short) (SC_H + 6)] & 0xFF);
            short lo = (short) (sc[(short) (SC_H + 7)] & 0xFF);
            // delta = hi*256 + lo seconds; window is WINDOW_SECONDS (< 2^15, fits short)
            if (hi > (short) (WINDOW_SECONDS >> 8)) return false;
            if (hi < (short) (WINDOW_SECONDS >> 8)) return true;
            return lo < (short) (WINDOW_SECONDS & 0xFF);
        }

        private static short ucmp(byte[] a, short ao, byte[] b, short bo) {
            for (short i = 0; i < 8; i++) {
                short x = (short) (a[(short)(ao+i)] & 0xFF);
                short y = (short) (b[(short)(bo+i)] & 0xFF);
                if (x != y) return (short) (x < y ? -1 : 1);
            }
            return 0;
        }

        /* HMAC-SHA256, key<=64 */
        private void hmacSha256(byte[] key, short kOff, short kLen,
                                byte[] msg, short mOff, short mLen,
                                byte[] out, short outOff) {
            for (short i = 0; i < 64; i++) {
                byte kb = (i < kLen) ? key[(short)(kOff+i)] : 0;
                sc[(short)(SC_PAD+i)] = (byte)(kb ^ 0x36);
            }
            sha256.reset();
            sha256.update(sc, SC_PAD, (short) 64);
            sha256.doFinal(msg, mOff, mLen, sc, SC_INFO);
            for (short i = 0; i < 64; i++) {
                byte kb = (i < kLen) ? key[(short)(kOff+i)] : 0;
                sc[(short)(SC_PAD+i)] = (byte)(kb ^ 0x5C);
            }
            sha256.reset();
            sha256.update(sc, SC_PAD, (short) 64);
            sha256.doFinal(sc, SC_INFO, (short) 32, out, outOff);
        }

        /* CRC16 (CRC-16/L variant per manual) over the sample public key blob.
         * Host cross-checks PubCrc; using a fixed constant here since the sample
         * pubkey is fixed. Replace with a real CRC over your provisioned key. */
        private short crc16l() {
            short crc = 0;
            // CRC over 04||X||Y of the ECC521 sample key
            crc = crc16Update(crc, (byte) 0x04);
            for (short i = 0; i < SAMPLE_DEV_PUB_X.length; i++) crc = crc16Update(crc, SAMPLE_DEV_PUB_X[i]);
            for (short i = 0; i < SAMPLE_DEV_PUB_Y.length; i++) crc = crc16Update(crc, SAMPLE_DEV_PUB_Y[i]);
            return crc;
        }
        private static short crc16Update(short crc, byte b) {
            crc ^= (short) ((b & 0xFF) << 8);
            for (short i = 0; i < 8; i++) {
                crc = ((crc & (short)0x8000) != 0) ? (short)((crc << 1) ^ 0x1021) : (short)(crc << 1);
            }
            return crc;
        }

        private void set521(javacard.security.ECKey k, boolean priv) {
            k.setFieldFP(P521_FP_B, (short) 0, (short) P521_FP_B.length);
            k.setA(P521_A_B, (short) 0, (short) P521_A_B.length);
            k.setB(P521_B_B, (short) 0, (short) P521_B_B.length);
            k.setG(P521_G_B, (short) 0, (short) P521_G_B.length);
            k.setR(P521_R_B, (short) 0, (short) P521_R_B.length);
            k.setK((short) 1);
            if (priv) ((ECPrivateKey) k).setS(SAMPLE_DEV_PRIV_D, (short) 0, (short) SAMPLE_DEV_PRIV_D.length);
            else {
                byte[] w = new byte[133];
                w[0] = 0x04;
                Util.arrayCopyNonAtomic(SAMPLE_DEV_PUB_X, (short) 0, w, (short) 1, (short) 66);
                Util.arrayCopyNonAtomic(SAMPLE_DEV_PUB_Y, (short) 0, w, (short) 67, (short) 66);
                ((ECPublicKey) k).setW(w, (short) 0, (short) 133);
            }
        }

        /* secp521r1 parameters as byte-array literals (66-byte field elements) */
        private static final byte[] P521_FP_B = {
            (byte)0x01,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
            (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
            (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
            (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
            (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
            (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
            (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
            (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
            (byte)0xFF,(byte)0xFF
        };
        private static final byte[] P521_A_B = {
            (byte)0x01,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
            (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
            (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
            (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
            (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
            (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
            (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
            (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
            (byte)0xFF,(byte)0xFC
        };
        private static final byte[] P521_B_B = {
            (byte)0x00,(byte)0x51,(byte)0x95,(byte)0x3E,(byte)0xB9,(byte)0x61,(byte)0x8E,(byte)0x1C,
            (byte)0x9A,(byte)0x1F,(byte)0x92,(byte)0x9A,(byte)0x21,(byte)0xA0,(byte)0xB6,(byte)0x85,
            (byte)0x40,(byte)0xEE,(byte)0xA2,(byte)0xDA,(byte)0x72,(byte)0x5B,(byte)0x99,(byte)0xB3,
            (byte)0x15,(byte)0xF3,(byte)0xB8,(byte)0xB4,(byte)0x89,(byte)0x91,(byte)0x8E,(byte)0xF1,
            (byte)0x09,(byte)0xE1,(byte)0x56,(byte)0x19,(byte)0x39,(byte)0x51,(byte)0xEC,(byte)0x7E,
            (byte)0x93,(byte)0x7B,(byte)0x16,(byte)0x52,(byte)0xC0,(byte)0xBD,(byte)0x3B,(byte)0xB1,
            (byte)0xBF,(byte)0x07,(byte)0x35,(byte)0x73,(byte)0xDF,(byte)0x88,(byte)0x3D,(byte)0x2C,
            (byte)0x34,(byte)0xF1,(byte)0xEF,(byte)0x45,(byte)0x1F,(byte)0xD4,(byte)0x6B,(byte)0x50,
            (byte)0x3F,(byte)0x00
        };
        private static final byte[] P521_G_B = {
            (byte)0x04,(byte)0x00,(byte)0xC6,(byte)0x85,(byte)0x8E,(byte)0x06,(byte)0xB7,(byte)0x04,
            (byte)0x04,(byte)0xE9,(byte)0xCD,(byte)0x9E,(byte)0x3E,(byte)0xCB,(byte)0x66,(byte)0x23,
            (byte)0x95,(byte)0xB4,(byte)0x42,(byte)0x9C,(byte)0x64,(byte)0x81,(byte)0x39,(byte)0x05,
            (byte)0x3F,(byte)0xB5,(byte)0x21,(byte)0xF8,(byte)0x28,(byte)0xAF,(byte)0x60,(byte)0x6B,
            (byte)0x4D,(byte)0x3D,(byte)0xBA,(byte)0xA1,(byte)0x4B,(byte)0x5E,(byte)0x77,(byte)0xEF,
            (byte)0xE7,(byte)0x59,(byte)0x28,(byte)0xFE,(byte)0x1D,(byte)0xC1,(byte)0x27,(byte)0xA2,
            (byte)0xFF,(byte)0xA8,(byte)0xDE,(byte)0x33,(byte)0x48,(byte)0xB3,(byte)0xC1,(byte)0x85,
            (byte)0x6A,(byte)0x42,(byte)0x9B,(byte)0xF9,(byte)0x7E,(byte)0x7E,(byte)0x31,(byte)0xC2,
            (byte)0xE5,(byte)0xBD,(byte)0x66,(byte)0x01,(byte)0x18,(byte)0x39,(byte)0x29,(byte)0x6A,
            (byte)0x78,(byte)0x9A,(byte)0x3B,(byte)0xC0,(byte)0x04,(byte)0x5C,(byte)0x8A,(byte)0x5F,
            (byte)0xB4,(byte)0x2C,(byte)0x7D,(byte)0x1B,(byte)0xD9,(byte)0x98,(byte)0xF5,(byte)0x44,
            (byte)0x49,(byte)0x57,(byte)0x9B,(byte)0x44,(byte)0x68,(byte)0x17,(byte)0xAF,(byte)0xBD,
            (byte)0x17,(byte)0x27,(byte)0x3E,(byte)0x66,(byte)0x2C,(byte)0x97,(byte)0xEE,(byte)0x72,
            (byte)0x99,(byte)0x5E,(byte)0xF4,(byte)0x26,(byte)0x40,(byte)0xC5,(byte)0x50,(byte)0xB9,
            (byte)0x01,(byte)0x3F,(byte)0xAD,(byte)0x07,(byte)0x61,(byte)0x35,(byte)0x3C,(byte)0x70,
            (byte)0x86,(byte)0xA2,(byte)0x72,(byte)0xC2,(byte)0x40,(byte)0x88,(byte)0xBE,(byte)0x94,
            (byte)0x76,(byte)0x9F,(byte)0xD1,(byte)0x66,(byte)0x50
        };
        private static final byte[] P521_R_B = {
            (byte)0x01,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
            (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
            (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
            (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
            (byte)0xFF,(byte)0xFA,(byte)0x51,(byte)0x86,(byte)0x87,(byte)0x83,(byte)0xBF,(byte)0x2F,
            (byte)0x96,(byte)0x6B,(byte)0x7F,(byte)0xCC,(byte)0x01,(byte)0x48,(byte)0xF7,(byte)0x09,
            (byte)0xA5,(byte)0xD0,(byte)0x3B,(byte)0xB5,(byte)0xC9,(byte)0xB8,(byte)0x89,(byte)0x9C,
            (byte)0x47,(byte)0xAE,(byte)0xBB,(byte)0x6F,(byte)0xB7,(byte)0x1E,(byte)0x91,(byte)0x38,
            (byte)0x64,(byte)0x09
        };


        /* P-256 helper mirrors the main applet's constants */
        static final class P256 {
            static void set(javacard.security.ECKey k) {
                k.setFieldFP(FP,(short)0,(short)FP.length); k.setA(A,(short)0,(short)A.length);
                k.setB(B,(short)0,(short)B.length); k.setG(G,(short)0,(short)G.length);
                k.setR(R,(short)0,(short)R.length); k.setK((short)1);
            }
            private static final byte[] FP = {
                (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01,
                (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
                (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
                (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF
            };
            private static final byte[] A = {
                (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01,
                (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
                (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
                (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFC
            };
            private static final byte[] B = {
                (byte)0x5A,(byte)0xC6,(byte)0x35,(byte)0xD8,(byte)0xAA,(byte)0x3A,(byte)0x93,(byte)0xE7,
                (byte)0xB3,(byte)0xEB,(byte)0xBD,(byte)0x55,(byte)0x76,(byte)0x98,(byte)0x86,(byte)0xBC,
                (byte)0x65,(byte)0x1D,(byte)0x06,(byte)0xB0,(byte)0xCC,(byte)0x53,(byte)0xB0,(byte)0xF6,
                (byte)0x3B,(byte)0xCE,(byte)0x3C,(byte)0x3E,(byte)0x27,(byte)0xD2,(byte)0x60,(byte)0x4B
            };
            private static final byte[] G = {
                (byte)0x04,(byte)0x6B,(byte)0x17,(byte)0xD1,(byte)0xF2,(byte)0xE1,(byte)0x2C,(byte)0x42,
                (byte)0x47,(byte)0xF8,(byte)0xBC,(byte)0xE6,(byte)0xE5,(byte)0x63,(byte)0xA4,(byte)0x40,
                (byte)0xF2,(byte)0x77,(byte)0x03,(byte)0x7D,(byte)0x81,(byte)0x2D,(byte)0xEB,(byte)0x33,
                (byte)0xA0,(byte)0xF4,(byte)0xA1,(byte)0x39,(byte)0x45,(byte)0xD8,(byte)0x98,(byte)0xC2,
                (byte)0x96,(byte)0x4F,(byte)0xE3,(byte)0x42,(byte)0xE2,(byte)0xFE,(byte)0x1A,(byte)0x7F,
                (byte)0x9B,(byte)0x8E,(byte)0xE7,(byte)0xEB,(byte)0x4A,(byte)0x7C,(byte)0x0F,(byte)0x9E,
                (byte)0x16,(byte)0x2B,(byte)0xCE,(byte)0x33,(byte)0x57,(byte)0x6B,(byte)0x31,(byte)0x5E,
                (byte)0xCE,(byte)0xCB,(byte)0xB6,(byte)0x40,(byte)0x68,(byte)0x37,(byte)0xBF,(byte)0x51,
                (byte)0xF5
            };
            private static final byte[] R = {
                (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
                (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
                (byte)0xBC,(byte)0xE6,(byte)0xFA,(byte)0xAD,(byte)0xA7,(byte)0x17,(byte)0x9E,(byte)0x84,
                (byte)0xF3,(byte)0xB9,(byte)0xCA,(byte)0xC2,(byte)0xFC,(byte)0x63,(byte)0x25,(byte)0x51
            };
        }
    }
}
