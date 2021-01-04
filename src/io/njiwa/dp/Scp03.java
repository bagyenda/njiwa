/*
 * Njiwa Open Source Embedded M2M UICC Remote Subscription Manager
 * 
 * 
 * Copyright (C) 2019 - , Digital Solutions Ltd. - http://www.dsmagic.com
 *
 * Njiwa Dev <dev@njiwa.io>
 * 
 * This program is free software, distributed under the terms of
 * the GNU General Public License.
 */ 

package io.njiwa.dp;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.njiwa.common.SDCommand;
import io.njiwa.common.Utils;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.KDFCounterBytesGenerator;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KDFCounterParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * @brief GP SCP03 functionality
 */
public class Scp03 {
    public static final byte[] null16b = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    public static final byte[] one16b = new byte[]{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01};

    public static final IvParameterSpec nullIv16 = new IvParameterSpec(null16b);
    private static final int C_MAC = 0x01, R_MAC = 0x10, C_DECRYPTION = 0x02, R_ENCRYPTION = 0x20;

    private static byte[] kdf(byte[] key, final byte derivation_constant, final byte[] context, final int blockbits) {
        // Sec 4.1.5 of GPC Ammend D
        final byte[] label = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, derivation_constant};
        try {
            ByteArrayOutputStream os = new ByteArrayOutputStream() {
                {
                    write(label);
                    write(0x00); // Separator
                    write((blockbits >> 8) & 0xFF);
                    write((blockbits & 0xFF));
                }
            };
            byte[] xa = os.toByteArray();
            BlockCipher cp = new AESEngine();
            CMac mac = new CMac(cp);
            KDFCounterBytesGenerator kdf = new KDFCounterBytesGenerator(mac);
            kdf.init(new KDFCounterParameters(key, xa, context, 8));
            byte[] out = new byte[blockbits / 8];
            kdf.generateBytes(out, 0, out.length);
            return out;
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }

    }

    public interface GetKey {
        byte[] baseSCP03key(int keyVersion, int keyID);
    }

    public static class Error extends Exception {
    } // For grouping only

    public static class InvalidCMAC extends Error {
        private String msg = "Invalid CMAC";

        public InvalidCMAC() {
        }

        public InvalidCMAC(String msg) {
            this.msg = msg;
        }

        @Override
        public String getMessage() {
            return msg;
        }
    }

    public static class ErrorResponse extends Error {
        public int errorcode;
        public byte[] data;

        public ErrorResponse() {
        }

        public ErrorResponse(int errorcode, byte[] resp) {
            this.errorcode = errorcode;
            this.data = resp;
        }

        @Override
        public String getMessage() {
            return String.format("Error in response code [%04x: %s]", errorcode, data == null ? "(null)" : Utils.HEX.b2H
                    (data));
        }
    }

    public static class Session {

        public State state = State.START;
        public byte[] hostChallenge;


        public byte[] cardChallenge;
        public byte[] cardCryptoGram;
        public byte[] hostCryptoGram;
        public int keyVersion = 0; // Defaults to zero as per spec
        public int keyID = 0;
        public int scpI = 0x70; // Per spec
        public byte[] diversificationData;
        public byte[] macChainingValue; // Starts out with sixteen zeros
        public byte[] encCounter; // Starts out with zeros
        public int counter;
        public Mode mode;
        // The keys
        public byte[] smac;
        public byte[] srmac;
        public byte[] senc;

        public Session() {
        }

        public Session(Mode mode) {
            this.mode = mode;
            this.state = State.START;
        }

        public Session(Mode mode, int keyVersion, int keyID) {
            this.mode = mode;
            this.keyVersion = keyVersion;
            this.keyID = keyID;
        }

        public static Session fromString(String input) throws Exception {
            byte[] in = Utils.urlDecode(input);
            String xinput = new String(in, StandardCharsets.UTF_8);
            return new ObjectMapper().readValue(xinput, Session.class);
        }

        private static void incrementCtr(byte[] ctr) {
            int n = ctr.length;
            for (int i = n - 1; i >= 0; i--)
                if (ctr[i] != (byte) 0xff) { // Carry forward check
                    ctr[i]++;
                    break;
                } else
                    ctr[i] = 0; // Carry forward
        }

        public Session copyOf() {
            // Make a copy of it by lazily serialising to string and then back.
            try {
                String s = new ObjectMapper().writeValueAsString(this);
                return new ObjectMapper().readValue(s, getClass());
            } catch (Exception ex) {
            }
            return null;
        }

        @Override
        public String toString() {
            try {
                String x = new ObjectMapper().writeValueAsString(this);
                return Utils.urlEncode(x.getBytes(StandardCharsets.UTF_8));
            } catch (Exception ex) {
            }
            return null;
        }

        private byte[] encryptData(byte[] data) {

            if (data.length > 0)
                try {
                    byte[] xdata = Utils.pad80(data, 16);
                    Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
                    Key k = new SecretKeySpec(senc, "AES");
                    c.init(Cipher.ENCRYPT_MODE, k, nullIv16); // Sec 6.2.6 of Ammend. D
                    byte[] iv = c.doFinal(encCounter);
                    c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));
                    data = c.doFinal(xdata); // Then encrypt data
                } catch (Exception ex) {
                }
            return data;
        }

        private byte[] decryptAndCheckMac(byte[] resp, int emode) throws Exception {
            // Do it based on mode
            byte[] encdata, r_mac = new byte[8];
            if (mode == Mode.TLV) {
                Utils.Pair<Integer, byte[]> xres = Utils.BER.decodeTLV(resp);
                encdata = xres.l;
                if ((xres.k >> 8) == 0x9F) // Error
                    throw new ErrorResponse(xres.k, encdata);
            } else {
                int sw1 = resp[resp.length - 2], sw2 = resp[resp.length - 1];
                encdata = Arrays.copyOf(resp, resp.length - 2);
                if (!SDCommand.APDU.isSuccessCode(sw1))
                    throw new ErrorResponse((sw1 << 8) | sw2, encdata);
            }
            System.arraycopy(encdata, encdata.length - 8, r_mac, 0, r_mac.length);
            Arrays.copyOf(encdata, encdata.length - 8);
            byte[] data;
            if (encdata.length > 0 && (emode & R_ENCRYPTION) != 0) {
                // Now decrypt. Use the existing iv
                Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
                Key k = new SecretKeySpec(senc, "AES");
                c.init(Cipher.ENCRYPT_MODE, k, nullIv16); // Sec 6.2.6 of Ammend. D
                byte[] icvblock = Arrays.copyOf(encCounter, encCounter.length);
                icvblock[icvblock.length - 1] = (byte) 0x80; // According to Sec 6.2.7 of Ammend. D
                byte[] iv = c.doFinal(icvblock);
                c.init(Cipher.DECRYPT_MODE, k, new IvParameterSpec(iv));
                data = c.doFinal(encdata);
                // Finally remove the padding...
                int i;
                for (i = data.length - 1; i > 0; i--)
                    if (data[i] == 0)
                        continue;
                    else if (data[i] == 0x80)
                        break;
                data = Arrays.copyOf(data, i);
            } else   // Else data is unchanged
                data = Arrays.copyOf(encdata, encdata.length);

            // Check mac: Always implied.
            byte[] forMac = Arrays.copyOf(macChainingValue, macChainingValue.length + resp.length);
            System.arraycopy(resp, 0, forMac, macChainingValue.length, resp.length);
            // Do the MAc: Sec 6.2.5 of Ammend. D
            BlockCipher cp = new AESEngine();
            CMac cmac = new CMac(cp);
            cmac.init(new KeyParameter(srmac));
            cmac.update(forMac, 0, forMac.length);
            byte[] out = new byte[cmac.getMacSize()];
            cmac.doFinal(out, 0);
            byte[] out_rmac = Arrays.copyOf(out, 8);
            if (!Arrays.equals(out_rmac, r_mac))
                throw new InvalidCMAC(String.format("Invalid RMAC, got [%s], expected [%s]", Utils.HEX.b2H(out), Utils.HEX
                        .b2H(r_mac)));
            incrementCtr(encCounter); // Bump encryption counter up
            return data;
        }

        private void encryptAndMac(SDCommand c, int emode) {
            boolean isapdu = c instanceof SDCommand.APDU;
            byte[] data = isapdu ? ((SDCommand.APDU) c).data : ((SDCommand.SCP03tCommand) c)
                    .data;
            byte[] edata = (emode & C_DECRYPTION) != 0 ? encryptData(data) : data;

            // C_MAC is implied. Always?
            try {
                ByteArrayOutputStream os = new ByteArrayOutputStream();
                os.write(macChainingValue);
                c.appendDataForCMAC(os, edata);
                byte[] input = os.toByteArray();
                // Do the MAc
                BlockCipher cp = new AESEngine();
                CMac cmac = new CMac(cp);
                cmac.init(new KeyParameter(smac));
                cmac.update(input, 0, input.length);
                byte[] out = new byte[cmac.getMacSize()];
                cmac.doFinal(out, 0);

                byte[] cmdMac = Arrays.copyOf(out, 8); // Copy first 8 bytes as c-mac
                System.arraycopy(out, 0, macChainingValue, 0, macChainingValue.length); // Copy new chaining value

                edata = Arrays.copyOf(edata, edata.length + cmdMac.length);
                System.arraycopy(cmdMac, 0, edata, edata.length, cmdMac.length);
                // Now rebuild the commands
                if (isapdu) {
                    SDCommand.APDU apdu = (SDCommand.APDU) c;
                    apdu.data = edata;
                    apdu.cla = (short) 0x84;
                } else {
                    SDCommand.SCP03tCommand cs = (SDCommand.SCP03tCommand) c;
                    cs.data = edata;
                    // Tag is unchanged. Could be 0x85 (for external auth) or 0x86 for regular data, so leave it alone
                }
            } catch (Exception ex) {
            }

        }

        public SDCommand scp03Command() throws Exception {
            return scp03Command(null);
        }

        public SDCommand scp03Command(SDCommand inputCommand) throws Exception {
            switch (state) {
                case START:
                    if (hostChallenge == null) {
                        hostChallenge = new byte[8];
                        SecureRandom sr = new SecureRandom();
                        sr.nextBytes(hostChallenge); // pseudo-random challenge required
                    }
                    if (mode == Mode.CAPDU)
                        return new SDCommand.APDU(0x80, 0x50, keyVersion, keyID, hostChallenge, (short) 256);
                    else {
                        // sec 4.1.3.3 sgp v3.1
                        byte[] data = new byte[8 + 1 + 1];
                        data[0] = (byte) keyVersion;
                        data[1] = (byte) keyID;
                        System.arraycopy(hostChallenge, 0, data, 2, hostChallenge.length);

                        return new SDCommand.SCP03tCommand(0x84, data);
                    }
                case AWAITING_AUTH: // Send external auth

                    int secLevel = 0x33; // According to SGP, c-decryption,r-encryption,c-mac,r-mac enabled
                    // And at this stage we wrap commands already...
                    SDCommand c;
                    if (mode == Mode.TLV) {
                        byte[] edata = new byte[9];
                        edata[0] = (byte) secLevel;
                        System.arraycopy(hostCryptoGram, 0, edata, 1, hostCryptoGram.length);

                        c = new SDCommand.SCP03tCommand(0x85, edata);
                    } else
                        c = new SDCommand.APDU(0x80, 0x82, secLevel, 0x0, hostCryptoGram);
                    // Now wrap the command
                    encryptAndMac(c, C_MAC); // Only MAC
                    encCounter = Arrays.copyOf(null16b, null16b.length);
                    macChainingValue = Arrays.copyOf(null16b, null16b.length); // Figure 6-3 of Ammend. D
                    return c;
                case AUTHENTICATED:
                    try {
                        encryptAndMac(inputCommand, C_MAC | C_DECRYPTION);
                    } catch (Exception ex) {
                        state = State.DEAD;
                        throw ex; // Re-throw it
                    }
                    return inputCommand;
                default:
                    throw new Exception("Unpexected command request in state: " + state);
            }

        }

        public byte[] processResponse(byte[] resp) throws Exception {
            return processResponse(resp, null);
        }

        public byte[] processResponse(byte[] resp, GetKey g) throws Exception {
            try {
                switch (state) {
                    case START:
                        if (mode == Mode.TLV) {
                            Utils.Pair<Integer, byte[]> res = Utils.BER.decodeTLV(resp);
                            if (res.k != 0x84) // Error should give us a tag of 9F 84
                                throw new Exception(String.format("Error in response, tag[%02x], data [%s] ", res.k,
                                        res.l));
                            resp = res.l;
                        } else {
                            int sw1 = resp[resp.length - 2];
                            int sw2 = resp[resp.length - 1];
                            if (!(sw1 == 0x90 && sw2 == 0x00))
                                throw new Exception(String.format("Failed external auth [%02x%02x", sw1, sw2));
                        }
                        // Fall through

                        diversificationData = new byte[10];
                        System.arraycopy(resp, 0, diversificationData, 0, 10);
                        int offset = 10;
                        keyVersion = resp[offset++];
                        int scpVersion = resp[offset++];
                        scpI = resp[offset++];
                        if (scpI != 0x70)
                            throw new Exception(String.format("Invalid SCP i parameter [%02x]", scpI));
                        cardChallenge = new byte[8];
                        System.arraycopy(resp, offset, cardChallenge, 0, 8);
                        offset += cardChallenge.length;
                        cardCryptoGram = new byte[8];
                        System.arraycopy(resp, offset, cardCryptoGram, 0, 8);
                        offset += cardCryptoGram.length;
                        byte[] ctr = new byte[3];
                        try {
                            System.arraycopy(resp, offset, ctr, 0, 3);
                            // Convert it to int. Right?
                        } catch (Exception ex) {
                        }

                        // Compute session keys
                        byte[] staticKey = g.baseSCP03key(keyVersion, keyID);
                        // Make the context parameter
                        byte[] context = Arrays.copyOf(hostChallenge, hostChallenge.length + cardChallenge.length);
                        System.arraycopy(cardChallenge, 0, context, hostChallenge.length, cardChallenge.length);

                        smac = kdf(staticKey, (byte) 0x06, context, 128); // Table 4-1 of GPC Ammend. D
                        senc = kdf(staticKey, (byte) 0x04, context, 128);
                        srmac = kdf(staticKey, (byte) 0x07, context, 128);
                        // Ignore KEK. Not used

                        // Verify card cryptogram
                        byte[] myCardCryptoGram = kdf(smac, (byte) 0, context, 64); // Check card cryptogram (Sec 6.2.2.2
                        // of Ammend D.
                        if (!Arrays.equals(myCardCryptoGram, cardCryptoGram)) {
                            state = State.DEAD;
                            throw new Exception(String.format("Failed to verify card cryptogram, got [%s], expected " +
                                    "[%s]", Utils.HEX.b2H(cardCryptoGram), Utils.HEX.b2H(myCardCryptoGram)));
                        }

                        hostCryptoGram = kdf(smac, (byte) 0x01, context, 64); // Compute host cryptogram
                        state = State.AWAITING_AUTH; // Move to next state
                        break;
                    case AWAITING_AUTH:
                        if (mode == Mode.TLV) {
                            Utils.Pair<Integer, byte[]> res = Utils.BER.decodeTLV(resp);
                            if (res.k != 0x85) // Error should give us a tag of 9F 84
                                throw new Exception(String.format("Error in response, tag[%02x], data [%s] ", res.k,
                                        res.l));
                            resp = res.l;
                            decryptAndCheckMac(resp, R_MAC); // This throws an exception on error, so we don't fall in
                            // below.
                        } else {
                            int sw1 = resp[resp.length - 2];
                            int sw2 = resp[resp.length - 1];
                            if (!(sw1 == 0x90 && sw2 == 0x00))
                                throw new Exception(String.format("Failed external auth [%02x%02x", sw1, sw2));
                        }
                        state = State.AUTHENTICATED; // Authenticated...

                        break;
                    case AUTHENTICATED:
                        // Verify mac and so forth
                        try {
                            return decryptAndCheckMac(resp, R_MAC | R_ENCRYPTION);
                        } catch (Exception ex) {
                            state = State.DEAD;
                            throw ex;
                        }
                        // break;
                    default:
                        Utils.lg.severe(String.format("Received unexpected data/response [%s] in state [%s]", resp,
                                state));
                        break;
                }
            } catch (Exception ex) {
            }
            return null;
        }

        public enum State {
            START, AWAITING_AUTH, AUTHENTICATED, DEAD
        }

        public enum Mode {TLV, CAPDU}
    }
}
