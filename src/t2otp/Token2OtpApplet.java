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
                    Util.arrayCopyNonAtomic(inBuf, (short) 1, scratch, SC_CTR, (short) 8);
                    enumState[0] = 1; /* cursor = 0 */
                    sendEnumPage(apdu);
                } else if (sub == SUB_READ_ONE || sub == SUB_GET_METADATA) {
                    cmdReadOne(apdu, inLen, sub);
                } else {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
                break;
            }
            case P2_ENUM_CONTINUE: {
                if (inLen < 8) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                if (enumState[0] == 0) ISOException.throwIt(SW_ENTRY_NOT_FOUND);
                Util.arrayCopyNonAtomic(inBuf, (short) 0, scratch, SC_CTR, (short) 8);
                sendEnumPage(apdu);
                break;
            }
            case P2_WRITE_SEED:
                cmdWriteSeed(apdu, inLen);
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
}
