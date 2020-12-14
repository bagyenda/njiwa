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

package io.njiwa.sr.ota;

import io.njiwa.common.SDCommand;
import io.njiwa.common.ServerSettings;
import io.njiwa.common.StatsCollector;
import io.njiwa.common.Utils;
import io.njiwa.common.model.Key;
import io.njiwa.common.model.KeyComponent;
import io.njiwa.common.model.KeySet;
import io.njiwa.common.model.TransactionType;
import io.njiwa.sr.Session;
import io.njiwa.sr.SmSrTransactionsPeriodicProcessor;
import io.njiwa.sr.model.*;
import io.njiwa.sr.transports.Sms;
import io.njiwa.sr.transports.Transport;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.persistence.EntityManager;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.Security;
import java.util.*;


/**
 * @brief This is the main 03.48 message encoder and decoder. It also implements general MO package reception.
 */
public class Ota {
    public static final int DES_NONE = 0;

    public static final String ISD_DEFAULT_TAR = "000000";
    // OTA handlers by TAR value (hex formatted)
    public static final byte[] ISD_DEFAULT_TAR_B;
    // Most of these are from ETS TS 101 220
    public static final short R_APDU_TAG = 0x23;
    public static final short Immediate_Action_TAG = 0x81;
    public static final short Script_Chaining_TAG = 0x83;
    public static final short Error_Action_Tag = 0x82;
    public static final short Command_Scripting_Template_Tag = 0xAA;
    public static final short Response_Scripting_Template_Definite_Length_Tag = 0xAB;
    public static final short Command_Scripting_Template_for_Indefinite_Length_Tag = 0xAE;
    public static final short Response_Scripting_Template_for_Indefinite_Length_Tag = 0xAF;
    public static final short Number_of_Executed_C_APDUS_Tag = 0x80;
    public static final short Immediate_Action_Response_Tag = 0x81;
    public static final short Bad_Format_Tag = 0x90;
    public static final byte[] SMS_STATIC_RPH = {0x02, 0x71, 0x00};

    static {
        // Initialise the default TAR
        ISD_DEFAULT_TAR_B = Utils.HEX.h2b(ISD_DEFAULT_TAR);
    }

    /**
     * @param input
     * @param transportType
     * @param msisdn
     * @param udh
     * @param em
     * @return the raw data and the OTA params
     * @throws Exception
     * @brief Remove and verify the 03.48/SCP 08 packaging from a received message
     */
    public static Utils.Triple<byte[], Params, Eis> unpackSCP80(byte[] input, Transport.TransportType transportType,
                                                                String msisdn, byte[] udh, EntityManager em) throws Exception {

// Check the UDH, then...

        ByteArrayInputStream is = new ByteArrayInputStream(input);
        int rpi;
        int rpl;
        int rhl;
        boolean isResp;
        SecurityDomain sd = null;
        ProfileInfo p = null;

        if (transportType != Transport.TransportType.SMS) { // e.g bip
            rpi = is.read();
            rpl = Utils.BER.decodeTLVLen(is);
            rhl = Utils.BER.decodeTLVLen(is);

            isResp = rpi == 0x02 || rpi == 0x04;
        } else {
            rpl = (int) Utils.BER.decodeInt(is, 2);
            rhl = is.read();
            rpi = 0;
            isResp = (udh != null && (udh[1] & 0xFF) == 0x71) || (rhl == 0x0a || rhl == 0x0E || rhl == 0x12);
        }

        if (!isResp && rhl != 0x15 && rhl != 0x11 && rhl != 0x0D)
            throw new Exception(String.format("Invalid OTA packet length: %d", rhl));
        else if (isResp && (transportType == Transport.TransportType.SMS) && rhl != 0x0a && rhl != 0x0E && rhl != 0x12)
            throw new Exception(String.format("Invalid SMS OTA response packet length: %d", rhl));

        int spi1;
        int spi2;
        int kic_byte;
        int kid_byte;

        if (!isResp) {
            spi1 = is.read();
            spi2 = is.read();
            kic_byte = is.read();
            kid_byte = is.read();
        } else {
            spi1 = 0;
            spi2 = 0;
            kic_byte = 0;
            kid_byte = 0;
        }
        byte[] TAR = new byte[3];

        if (is.read(TAR) != 3)
            throw new Exception(String.format("Invalid TAR length in %s OTA packet", isResp ? "MO" : "MT"));

        // Find profile
        Eis eis = Eis.findByMsisdn(em, msisdn); // Get EIS
        p = ProfileInfo.findProfileByTAR(eis, TAR, true); // Get profile

        // Now get SD. If profile is NULL, then SD is implicitly the ISD-R
        if (p == null) sd = eis.findISDR();
        else sd = SecurityDomain.findByTar(eis, TAR);

        int kic_keynum = -1;
        int kid_keynum = -1;
        byte[] kic = null;
        byte[] kid = null;
        if (isResp) {
            // Implicit security
            Utils.Pair<KeyComponent, KeyComponent> kp = sd.findFirstSCP80KeyComponents();
            if (kp != null) {
                if (kp.k != null) {
                    kic_byte = kp.k.to102_225_keybyte();
                    kic = kp.k.byteValue();
                    kic_byte = kp.k.to102_225_keybyte();
                }
                if (kp.l != null) {
                    kid_byte = kp.l.to102_225_keybyte();
                    kid = kp.l.byteValue();
                    kid_byte = kp.l.to102_225_keybyte();
                }
            } else spi1 = 0;

            int crypto_mask = kic != null ? (0x1 << 2) : 0;
            spi1 = (crypto_mask | (kid != null ? 0x02 | (spi1 & ~0x03) : spi1));

            spi1 |= kid != null ? 0x2 : kic != null ? 0x01 : 0;
        }

        if (kic == null && (kic_byte & 0x0F) != DES_NONE && spiHasEncryption(spi1)) {
            kic_keynum = (kic_byte & 0xFF) >> 4;
            int typeNibble = (kic_byte & 0xF);
            Utils.Pair<Integer, byte[]> r = Key.findKeyValue(sd, KeySet.Type.SCP80, kic_keynum, typeNibble,
                    Key.KIC_KEY_IDENTIFIER);
            kic = r.l;
        }

        if (kid == null && (kid_byte & 0x0F) != DES_NONE && spiHasCryptoCrc(spi1)) {
            kid_keynum = (kid_byte & 0xFF) >> 4;
            int typeNibble = (kid_byte & 0xF);
            Utils.Pair<Integer, byte[]> r = Key.findKeyValue(sd, KeySet.Type.SCP80, kid_keynum, typeNibble,
                    Key.KID_KEY_IDENTIFIER);
            kid = r.l;
        }

        byte[] cryptData = Utils.getBytes(is);

        byte[] decData;
        if ((kic_byte & 0x0F) != DES_NONE) decData = Crypt.decrypt(cryptData, kic, kic_byte & 0x0F);
        else decData = cryptData;

        // Reset reader
        is = new ByteArrayInputStream(decData);
        byte[] counterBytes = new byte[5];
        is.read(counterBytes);
        // long counter = Utils.decodeBerInt(counterBytes, 5);

        int pad = is.read();

        byte[] crc;
        byte[] statusCode = null;
        if (isResp) {
            int crc_len = rhl - 3 - 5 - 1 - 1;
            statusCode = new byte[1];
            is.read(statusCode);
            if (crc_len > 0) {
                crc = new byte[crc_len];
                is.read(crc);
            } else crc = null;
        } else {
            // Check stuff.
            boolean crcCrypto = ((spi1 >> 1) & 0x01) != 0;

            if ((spi1 & 0x03) != 0) {
                crc = new byte[crcCrypto ? 8 : 4];
                is.read(crc);
            } else crc = new byte[0];
        }

        ByteArrayOutputStream osPkg = new ByteArrayOutputStream();
        if ((spi1 & 0x03) != 0) {
            // For verify crc
            if (transportType != Transport.TransportType.SMS) {
                osPkg.write(rpi);
                Utils.BER.appendTLVlen(osPkg, rpl);
                Utils.BER.appendTLVlen(osPkg, rhl);
            } else {
                // According to 3GPP TS 31 115 (Sec 4.4/4.5), we add 02 71 00 before rpl
                osPkg.write(SMS_STATIC_RPH);
                Utils.appendEncodedInteger(osPkg, rpl, 2);
                osPkg.write(rhl);
            }

            if (!isResp) osPkg.write(new byte[]{(byte) spi1, (byte) spi2, (byte) kic_byte, (byte) kid_byte});
            osPkg.write(TAR);
        }

        // Get data after counter, padding, status code and CC removal.
        byte[] plainData = Utils.getBytes(is);
        if (osPkg.size() > 0) { // We need to check CRC
            byte[] cheader = osPkg.toByteArray();
            byte[] xCrc = Checksum.get(spi1, kid_byte, kid, cheader, counterBytes, pad, statusCode != null ?
                    statusCode[0] : null, plainData);
            if (!Arrays.equals(xCrc, crc)) throw new Exception("CRC mismatch in OTA packet");
        }

        // Remove padding
        if (plainData.length - pad > 0) plainData = Arrays.copyOf(plainData, plainData.length - pad);

        Params otaParams = new Params(spi1, spi2, kic_keynum, kid_keynum, TAR, counterBytes, p, sd);
        if (statusCode != null) otaParams.responseStatusCode = statusCode[0];
        return new Utils.Triple<>(plainData, otaParams, eis);
    }

    /**
     * @param in
     * @param spi1
     * @param has_enc
     * @return
     * @brief Perform the 03.48 data padding
     */
    private static Utils.Pair<byte[], Integer> padData(byte[] in, int spi1, boolean has_enc) {
        boolean cryptoCrc = ((spi1 >> 1) & 0x01) != 0;
        boolean hasRc = (spi1 & 0x01) != 0 && (spi1 & 0x02) == 0;

        if ((spi1 & 0x03) == 0 && !has_enc) return new Utils.Pair<>(in, 0); // No padding required

        int ccLen = (cryptoCrc ? 8 : (hasRc ? 4 : 0));

        int len = 5 + 1 + ccLen + in.length; // CNTR (5 bytes) + PCNTR (1 byte) + CCLen (variable) -- Table 2 of ETSI
        // TS 102 225

        int padTo;
        if (has_enc || cryptoCrc) padTo = 16; // We use AES, so pad to 16 always...
        else if (hasRc) padTo = 4;
        else padTo = 0;

        int padCtr;
        if (padTo > 0) {
            int xpadTo = padTo - 1;
            padCtr = ((len + xpadTo) & ~xpadTo) - len;

            // Now add zeros
            in = Arrays.copyOf(in, in.length + padCtr);
        } else padCtr = 0;

        return new Utils.Pair<>(in, padCtr);
    }

    public static boolean spiHasCryptoCrc(int spi1) {
        return ((spi1 >> 1) & 0x1) != 0;
    }

    public static boolean spiHasEncryption(int spi1) {
        return ((spi1 >> 2) & 0x01) == 1;
    }

    public static boolean spiHasCounter(int spi1) {
        return ((spi1 >> 3) & 0x03) != 0;
    }

    public static int estimatePkLen(int dlen, int spi1, boolean hasEnc, boolean hasCpi) {
        boolean crypto_crc = spiHasCryptoCrc(spi1);
        boolean hasRc = (spi1 & 0x01) != 0 && (spi1 & 0x02) == 0;
        int chl = (crypto_crc ? 21 : (spi1 & 0x03) != 0 ? 17 : 13);
        int cpl = dlen + (hasCpi ? Utils.BER.getTlvLength(chl) : 1) + chl;

        int padTo;
        if (hasEnc || crypto_crc) padTo = 8;
        else if (hasRc) padTo = 4;
        else padTo = 0;

        int pkgLen = 5 + 1 + (crypto_crc ? 8 : (hasRc ? 4 : 0)) + dlen;

        int pad_ctr;
        if (padTo > 0) {
            int xpad_to = padTo - 1;
            pad_ctr = ((pkgLen + xpad_to) & ~xpad_to) - pkgLen;
        } else pad_ctr = 0;
        cpl += pad_ctr;
        /* BIP packet includes CPI and cpl is tlv_encoded. For sms cpl = 2 bytes */
        return cpl + (hasCpi ? (1 + Utils.BER.getTlvLength(cpl)) : 2);
    }

    /**
     * Make a package for a security domain.
     *
     * @param session        - The current session
     * @param securityDomain - The security domain
     * @param in             - the data
     * @param cpi            - the CPI byte
     * @param counter        - The current counter
     * @return
     * @throws Exception
     * @brief Create the GSM 03.48 OTA packet, given its parameters
     */
    public static byte[] createSCP80Pkg(Session session, SecurityDomain securityDomain, byte[] TAR, byte[] in,
                                        int cpi, boolean porOnError, Long counter) throws Exception {

        int spi1 = ServerSettings.getDefault_ota_spi1();
        int spi2 = ServerSettings.getDefault_ota_spi2();
        boolean hasEnc = spiHasEncryption(spi1);
        boolean hasCrc = spiHasCryptoCrc(spi1);

        // If Por On error only, remove por.
        if (porOnError & (spi2 & 0x03) != 0) {
            spi2 &= ~0x3;
            spi2 |= 0x02;
        }
        KeyComponent kic = null, kid = null;
        // Look for kic and kid.
        try {
            Utils.Pair<KeyComponent, KeyComponent> kp = securityDomain.findFirstSCP80KeyComponents();
            kic = hasEnc ? kp.k : null;
            kid = hasCrc ? kp.l : null;
        } catch (Exception ex) {
            throw new Exception("Invalid: No matching SCP80 key set in security domain");
        }
        return createSCP80Pkg(session, in, cpi, kic, kid, spi1, spi2, TAR, counter);
    }

    /**
     * @param gwSession
     * @param in
     * @param cpi
     * @param kicComponent - The Kic key set to use
     * @param kidComponent - The kic to use
     * @param spi1
     * @param spi2
     * @param TAR
     * @param counter
     * @return
     * @throws Exception
     * @brief Create the GSM 03.48 OTA packet, given its parameters
     */
    public static byte[] createSCP80Pkg(Session gwSession, byte[] in, int cpi, KeyComponent kicComponent,
                                        KeyComponent kidComponent, int spi1, int spi2, byte[] TAR, Long counter) throws Exception {
        int kic_byte = 0;
        int kid_byte = 0;
        byte[] kic = null;
        byte[] kid = null;

        String msisdn = gwSession.getMsisdn();
        KeySet keySet = kicComponent != null ? kicComponent.getKey().getKeyset() : kidComponent != null ?
                kidComponent.getKey().getKeyset() : null;
        if (kicComponent != null && TAR == null) {
            // Find first TAR
            String[] tarList = kicComponent.getKey().getKeyset().getSd().getTARsAsList();
            TAR = Utils.HEX.h2b(tarList[0]);
        }

        if (spiHasEncryption(spi1)) try {
            kic = kicComponent.byteValue();
            kic_byte = kicComponent.to102_225_keybyte();
        } catch (Exception ex) {
            gwSession.error("Failed to find kic with index #%s for [%s]", kicComponent != null ?
                    kicComponent.toString() : "(null)", msisdn);
        }

        if (spiHasCryptoCrc(spi1)) try {
            kid = kidComponent.byteValue();
            kid_byte = kidComponent.to102_225_keybyte();
        } catch (Exception ex) {
            gwSession.error("Failed to find/get  kid with index #%d for [%s]", kidComponent != null ?
                    kidComponent.toString() : "(null)", msisdn);
        }
        int crypto_mask = kic != null ? (0x1 << 2) : 0;
        int xspi1 = (crypto_mask | (kid != null ? 0x02 | (spi1 & ~0x03) : spi1));
        byte[] counterBytes;
        if (spiHasCounter(spi1) && keySet != null) { // Counter requested.
            if (counter == null)  // Bump the RFM counter
                counter = gwSession.last_rfm_counter = keySet.bumpCounter(gwSession.entityManager);
            counterBytes = Utils.encodeInteger(counter, 5);
        } else counterBytes = new byte[5]; // All zeros by default

        if ((xspi1 & 0x03) == 0 && kid != null) xspi1 |= 0x01; // Force a checksum if the data is encrypted

        if (kic == null) xspi1 &= ~0x04; // Clear ciphering
        xspi1 &= ~(0x03 << 6); // Clear reserved bits
        return createSCP80Pkg(in, cpi, counterBytes, kic_byte, kid_byte, xspi1, spi2, kic, kid, TAR);
    }

    /**
     * Create the raw OTA package given the raw data
     *
     * @param in
     * @param cpi
     * @param counter
     * @param kic_byte
     * @param kid_byte
     * @param spi1
     * @param spi2
     * @param kic
     * @param kid
     * @param TAR
     * @return
     * @throws Exception
     * @brief Create the GSM 03.48 OTA packet, given its parameters. This is the base method
     */
    private static byte[] createSCP80Pkg(byte[] in, int cpi, byte[] counter, int kic_byte, int kid_byte, int spi1,
                                         int spi2, byte[] kic, byte[] kid, byte[] TAR) throws Exception {
        if (counter.length != 5) throw new Exception("Invalid length of RFM counter");

        if (TAR.length != 3) throw new Exception("Invalid TAR length");
        boolean enc = ((spi1 >> 2) & 0x01) != 0;
        boolean crypto_crc = ((spi1 >> 1) & 0x1) != 0;
        // int encType = enc ? (kic_byte & 0x0F) : DES_NONE;
        // int crcType = crypto_crc ? (kid_byte & 0x0f) : DES_NONE;
        Utils.Pair<byte[], Integer> px = padData(in, spi1, enc);
        in = px.k;
        int pcntr = px.l;


        /* cpl should calculated as 18 (or 22) + length of data because:
         * chl:1,spi:2,kic:1,kid:1,tar:3,cntr:5,pcntr:1,rc:(0,4,8)
         */


        int hlen;
        int chl = hlen = (crypto_crc ? 21 : (spi1 & 0x03) != 0 ? 17 : 13);
        int cpl = in.length + ((cpi >= 0) ? Utils.BER.getTlvLength(chl) : 1) + hlen; // Lenght + padding

        ByteArrayOutputStream osPkg = new ByteArrayOutputStream();
        if (cpi >= 0) { // If we are using ETSI 102 225 format
            osPkg.write(cpi);
            Utils.BER.appendTLVlen(osPkg, cpl);
            Utils.BER.appendTLVlen(osPkg, chl);
        } else {
            Utils.appendEncodedInteger(osPkg, cpl, 2);
            osPkg.write(chl & 0xFF);
        }
        osPkg.write(new byte[]{(byte) (spi1 & 0xFF), (byte) (spi2 & 0xFF), (byte) (kic_byte & 0xFF),
                (byte) (kid_byte & 0xFF)});
        osPkg.write(TAR);

        /* crc on cpl + chl + spi + KIc + KID + TAR + CNTR + */
        byte[] crc = Checksum.get(spi1, kid_byte, kid, osPkg.toByteArray(), counter, pcntr, null, in);
        // Utils.lg.info(String.format("CRC: [%s]", Utils.b2H(crc)) );
        if (!enc) {
            osPkg.write(counter);
            osPkg.write(pcntr);
            osPkg.write(crc);
            osPkg.write(in);
        } else {
            // Make package for encryption
            ByteArrayOutputStream pkg = new ByteArrayOutputStream();
            pkg.write(counter);
            pkg.write(pcntr);
            pkg.write(crc);
            pkg.write(in);

            byte[] clearpkg = pkg.toByteArray();
            //  Utils.lg.info(String.format("Clear PKG [%s], kic [%s]", Utils.b2H(clearpkg), Utils.b2H(kic)));

            byte[] osEnc = Crypt.encrypt(clearpkg, kic, kic_byte & 0x0F);
            //  Utils.lg.info(String.format("Enc Pkg [%s]",  Utils.b2H(osEnc)));
            osPkg.write(osEnc);
        }

        return osPkg.toByteArray();
    }

    /**
     * @param input         The received message
     * @param transportType The type of transport
     * @param msisdn        The sender
     * @param udh           User data header, if any
     * @param em            Persistence object (JPA)
     * @throws Exception
     * @brief Receive and process the MO packet.
     * @details GSM 03.48 unpack it, then, based on the TAR value, find the right response handler and call it to
     * process the packet.
     * If a response is returned, send it out directly again.
     */
    public static void receiveMO(final byte[] input, final Transport.TransportType transportType, final String msisdn
            , final byte[] udh, EntityManager em) throws Exception {

        final Utils.Triple<byte[], Params, Eis> r = unpackSCP80(input, transportType, msisdn, udh, em);
        final Params p = r.l;
        final String TAR = p.getTARasString();


        Eis eis = r.m; // Eis.findByMsisdn(em, msisdn);
        Session session = new Session(em, eis);

        // Count MO pkt
        StatsCollector.recordTransportEvent(transportType, Transport.PacketType.MO);

        byte[] res = Ota.processMO(r.k, p, transportType, session, em);

        if (res != null && res.length > 0) {
            Transport sender = transportType.toTransport();
            Transport.Context ctx = sender.getContext(session.getEuicc(), p, 0, 1);


            sender.sendOTA(session, p, em, ctx, null, 0, "", "MO Response", res);
        }
    }

    /**
     * @param dlen
     * @return
     * @brief Count the number of SMS in a message
     */
    public static int smsCount(int dlen) {
        if (dlen + 3 <= Sms.MAX_SMS_OCTETS) return 1;
        int n = 1;
        dlen = dlen < (Sms.MAX_SMS_OCTETS - 8) ? 0 : dlen - (Sms.MAX_SMS_OCTETS - 8); // First UDH is slightly larger.
        n += Utils.ROUND(dlen, Sms.MAX_SMS_OCTETS - 6) / (Sms.MAX_SMS_OCTETS - 6);

        return n;
    }

    /**
     * @param capdus     - The C-APDU sequence
     * @param immediates - Immediate-Action stuff, if any
     * @return
     * @brief Combines capdus and immediates
     */
    public static byte[] combineCommandTlvs(final byte[] capdus, final byte[] immediates) throws Exception {
        ByteArrayOutputStream os = new ByteArrayOutputStream() {
            {
                try {
                    write(capdus);
                    if (immediates != null) write(immediates);
                } catch (Exception ex) {
                }
            }
        };
        ByteArrayOutputStream xos = new ByteArrayOutputStream();
        if (ServerSettings.Constants.useIndefiniteCodingInExpandedFormat) {
            xos.write(new byte[]{(byte) Command_Scripting_Template_for_Indefinite_Length_Tag, (byte) 0x80});
            xos.write(os.toByteArray());
            xos.write(new byte[]{0, 0}); // End of...
        } else Utils.BER.appendTLV(xos, Command_Scripting_Template_Tag, os.toByteArray());
        return xos.toByteArray();
    }

    /**
     * @param otaParams the OTA parameters
     * @return the bytes to be sent, and the last index in the APDU list
     * @throws Exception
     * @brief Construct a package to be wrapped using 03.48
     */
    public static Utils.Pair<byte[], Integer> mkOTAPkg(Params otaParams, List<byte[]> l, int startIndex,
                                                       HasEnoughOtaBuffer enoughOtaBuffer) throws Exception {


        // Check SPI1, force some flags
        if (((otaParams.spi1 >> 3) & 0x03) == 0) {
            if (!otaParams.forcedSpi1) otaParams.spi1 = (0x02 << 3) | (otaParams.spi1 & 0x07);
        }

        if ((otaParams.spi2 & 0x03) == 0) otaParams.forceDLR = true; // Force DLR tracking


        ScriptChaining chainingType = ScriptChaining.fromOTAParams(startIndex, l.size());
        final byte[] sdata = otaParams.allowChaining ? chainingType.toBytes() : new byte[0]; // Put script chaining
        // data in first
        int cursize = sdata.length + (ServerSettings.Constants.useIndefiniteCodingInExpandedFormat ? 2 : 1 + 4); //
        // Assume that definite coding
        // has a tag+length of 5, followed by chaining if any

        ByteArrayOutputStream odata = new ByteArrayOutputStream() {
            {
                write(sdata); // Put script chaining data in first
            }
        };
        // Now make the data stuff

        ByteArrayOutputStream xos = new ByteArrayOutputStream();
        int i = startIndex;
        try {
            do {
                byte[] data = l.get(i); // At this point the APDUs should already be split.
                if (!enoughOtaBuffer.hasEnoughBuffer(cursize + data.length)) break;
                odata.write(data);
                cursize += data.length;
                otaParams.numApdus++;

                i++; // Forward
            } while (i < l.size());


            // Now wrap the whole thing in a Command Scripting Template TAG

            byte[] commandTlvs = odata.toByteArray();
            if (ServerSettings.Constants.useIndefiniteCodingInExpandedFormat) {
                xos.write(new byte[]{(byte) Command_Scripting_Template_for_Indefinite_Length_Tag, (byte) 0x80});
                xos.write(commandTlvs);
                xos.write(new byte[]{0x00, 0x00}); // As per Sec 5.2.1 of ETSI TS 102 226 v12
            } else { // Use definite coding.
                xos.write(Command_Scripting_Template_Tag);
                Utils.BER.appendTLVlen(xos, commandTlvs.length);
                xos.write(commandTlvs);
            }
        } catch (Exception ex) {
        }
        otaParams.allowChaining = false; // Prevent chaining. Right?

        return new Utils.Pair<>(xos.toByteArray(), i);
    }

    /**
     * @param data          the data received after Command TLV Tag and length have been removed
     * @param transportType
     * @param session
     * @return
     * @brief Process a notification from the SD-SR according to Sec 4.1.1.11 of SGP doc
     */
    public static SmSrTransaction processNotification(byte[] data, Transport.TransportType transportType,
                                                      Session session) {
        try {
            // Try to parse the notification, first and foremost.
            NotificationMessage msg = NotificationMessage.parseNotification(session.entityManager,
                    new ByteArrayInputStream(data));
            // Set Eis?
            session.setEuicc(msg.eis);
            SmSrTransaction tr = msg.eis.processNotification(msg, session.entityManager);
            Utils.lg.info(String.format("Received and processed notification [%s]", msg));
            return tr;
        } catch (Exception ex) {
            Utils.lg.severe(String.format("Failed to process notification [%s]: %s", Utils.HEX.b2H(data), ex));
        }

        return null; // Return nothing.
    }

    public static byte[] processMO(byte[] inData, Params otaParams, Transport.TransportType transportType,
                                   Session session, EntityManager em) throws Exception {
        // Get a session, look for the RFM app, try and look for a handler.


        String msisdn = session.getMsisdn();
        String reqId = otaParams.mkRequestID();
        byte[] content = null;
        // First, parse the response
        ResponseHandler.RemoteAPDUStructure resp = ResponseHandler.RemoteAPDUStructure.parse(inData);
        SmSrTransaction bt;
        if (resp instanceof ResponseHandler.GenericEuiccResponse) {
            ResponseHandler.GenericEuiccResponse c = (ResponseHandler.GenericEuiccResponse) resp;
            processNotification(c.getData(), transportType, session);
        } else if ((bt = SmSrTransaction.findTransaction(em, msisdn, reqId)) != null) {
            Utils.lg.info(String.format("Received 03.48 return message from [%s] with request ID [%s] mapped to " +
                    "transaction [%s]", msisdn, reqId, bt));
            // We found it!
            Transport.MessageStatus msgStatus = bt.getTransportMessageStatus(); // We need this
            SmSrTransaction.Status tstatus = bt.getStatus();
            TransactionType tobj = bt.getTransObject();
            byte[] output = resp.getData();
            boolean successPor = otaParams.responseStatusCode == 0;
            Utils.Quad<Boolean, Boolean, String, Ota.ResponseHandler.ETSI102226APDUResponses> res =
                    Ota.ResponseHandler.ETSI102226APDUResponses.examineResponse(output);
            boolean success = successPor && res.k;
            boolean retry = res.l;
            String formattedResult = res.m;
            boolean continueProcessing;
            Transport msgStatusHandler = msgStatus.toTransport();

            if (msgStatusHandler != null)
                continueProcessing = msgStatusHandler.processTransMessageStatus(em, bt, success, retry, inData);
            else continueProcessing = true;
            // Run the updates, if we should continue processing
            if (continueProcessing) try {
                tobj.setResponses(res.o);
                tobj.handleResponse(em, bt.getId(), success ? TransactionType.ResponseType.SUCCESS :
                        TransactionType.ResponseType.ERROR, reqId, output);
                // Process response and Determine if we need to send again
            } catch (Exception ex) {
            }


            String xdata = formattedResult != null ? formattedResult : Utils.HEX.b2H(inData);
            SmSrTransaction.Status new_status = bt.statusFromResponse(success, retry);

            if (continueProcessing) {
                bt.updateStatus(em, new_status); // Will also run updates

                Date dt = new_status != SmSrTransaction.Status.Ready ? Utils.infiniteDate :
                        Calendar.getInstance().getTime();
                bt.setNextSend(dt); // Set next date
                bt.setLastupdate(Calendar.getInstance().getTime());
                if (success) bt.setLastrequestID(null); // Clear request ID.
                bt.setSimStatusCode(xdata);
                if (success) bt.setSimResponse("");
            }

            // em.persist(bt); // Save it
            // em.flush(); // Force it out
            if (new_status == SmSrTransaction.Status.Completed || new_status == SmSrTransaction.Status.Error)
                bt.deleteTransactionRequestIds();
            // SmSrTransactionRequestId.deleteTransactionRequestIds(em, bt.getId());

            if (continueProcessing && success) {
                SmSrTransaction tnext = bt.findNextAvailableTransaction(em);
                if (tnext != null) {
                    tnext.setNextSend(Calendar.getInstance().getTime());
                    SmSrTransactionsPeriodicProcessor.sendTrans(em, tnext); // Send Next one, if any
                }
            }

            try {
                transportType.toTransport().postProcessRecvdTransaction(em, bt, tstatus, msgStatus); // Post
                // process for transport, if any
            } catch (Exception ex) {

            }

            // Now map the msg status to a transport and let that transport tell us what to do.
        } else
            Utils.lg.severe(String.format("Failed to find OTA request for [%s], request ID was [%s]", msisdn, reqId));


        return content;
    }

    public enum ExpectedOtaResponseFormat {
        EXPANDED, COMPACT, NONE
    }

    public enum ScriptChaining {
        NOCHAINING, FIRST_SCRIPT_DELETE_ON_RESET, FIRST_SCRIPT_KEEP_ON_RESET, SUBSEQUENT_SCRIPT_MORE_TO_FOLLOW,
        LAST_SCRIPT;

        public static ScriptChaining fromOTAParams(int startPos, int len) {
            boolean firstData = startPos == 0;
            boolean lastData = startPos >= len - 1;
            if (firstData && lastData) return NOCHAINING;
            else if (firstData) return FIRST_SCRIPT_DELETE_ON_RESET;
            else if (lastData) return LAST_SCRIPT;
            else return SUBSEQUENT_SCRIPT_MORE_TO_FOLLOW;
        }

        public byte[] toBytes() {
            byte val;
            switch (this) {
                case NOCHAINING:
                    return new byte[0];
                case FIRST_SCRIPT_DELETE_ON_RESET:
                    val = 0x01;
                    break;
                case FIRST_SCRIPT_KEEP_ON_RESET:
                    val = 0x11;
                    break;
                case SUBSEQUENT_SCRIPT_MORE_TO_FOLLOW:
                    val = 0x02;
                    break;
                case LAST_SCRIPT:
                default:
                    val = 0x03;
                    break;
            }
            return new byte[]{(byte) Ota.Script_Chaining_TAG, 0x01, val};
        }
    }

    public interface HasEnoughOtaBuffer {
        boolean hasEnoughBuffer(long pktSize);
    }

    public static class Crypt {
        // Do encryption

        // Lower nibble of the KID as per GSM 03.48
        public static final int DES_CBC = 0x01;
        public static final int TRIBLE_DES_CBC2 = 0x05;
        public static final int TRIBLE_DES_CBC3 = 0x09;
        public static final int AES_CBC = 0x02; // SGP.02 v4.1 Appendix D says this should be 0x2

        static {
            // Need to add BouncyCastle as our provider here...
            Security.addProvider(new BouncyCastleProvider());
        }

        /**
         * @param in   The input
         * @param key  the (3)DES/AES key
         * @param mode The encryption/decryption mode
         * @return encrypted output
         * @throws Exception
         * @brief Perform the encryption of the OTA package as required. Use The Bouncy Castle package to provide
         * cryptographic
         * services
         */
        private static byte[] perform(byte[] in, int keyType, byte[] key, int mode) throws Exception {
            byte[] iv = keyType == AES_CBC ? new byte[16] : new byte[8];
            return perform(in, keyType, key, mode, iv); // With empty IV
        }

        public static byte[] perform(byte[] in, int keyType, byte[] key, int mode, byte[] inputIv) throws Exception {
            IvParameterSpec iv = new IvParameterSpec(inputIv);

            // Encrypt based key size
            if (in.length % 8 != 0) throw new Exception("Invalid input size. Must be a multiple of 8 bytes");
            if (key.length % 8 != 0) throw new Exception("Invalid key size. Must be a multiple of 8 bytes");

            if (key.length < 8 || key.length > 24)
                throw new Exception("Invalid key size. Must be a multiple of 8, 16 or 24 bytes");

            String xkeytype = keyType == AES_CBC ? "AES" : (key.length == 16 || key.length == 24) ? "DESede" : "DES";


            SecretKey keySpec = new SecretKeySpec(key, xkeytype);

            Cipher cipher = Cipher.getInstance(xkeytype + "/CBC/NoPadding", ServerSettings.Constants.jcaProvider);
            cipher.init(mode, keySpec, iv);

            byte[] out = cipher.doFinal(in);

            return out;
        }

        /**
         * @param in
         * @param key
         * @return
         * @throws Exception
         * @brief Perform DES encryption
         */
        public static byte[] encrypt(byte[] in, byte[] key, int keyType) throws Exception {
            return perform(in, keyType, key, Cipher.ENCRYPT_MODE);
        }

        /**
         * @param in
         * @param key
         * @return
         * @throws Exception
         * @brief Perform DES decryption
         */
        public static byte[] decrypt(byte[] in, byte[] key, int keyType) throws Exception {
            return perform(in, keyType, key, Cipher.DECRYPT_MODE);
        }

    }

    /**
     * @brief The CRC32 and Crypto Checksum computation functions
     */
    private static class Checksum {
        // Checksum stuff.

        public static byte[] get(int spi1, int kid_byte, byte[] kid, byte[] cheader, byte[] counter, int pcntr,
                                 Byte statusCode, byte[] data) throws Exception {

            if ((spi1 & 0x03) == 0) return new byte[0]; // No checksum requested

            boolean crypto_crc = ((spi1 >> 1) & 0x01) != 0;
            ByteArrayOutputStream os = new ByteArrayOutputStream();

            os.write(cheader);

            os.write(counter);
            os.write((byte) pcntr);
            if (statusCode != null) os.write(statusCode);
            os.write(data);

            // Utils.lg.info(String.format("HDR: %s", Utils.b2H(os.toByteArray())));
            if (!crypto_crc) {
                long x = CRC32(os.toByteArray());

                return Utils.encodeInteger(x, 4);
            }

            int mode = kid_byte & 0x0F;
            if (mode != Crypt.DES_CBC && mode != Crypt.TRIBLE_DES_CBC2 && mode != Crypt.TRIBLE_DES_CBC3 && mode != Crypt.AES_CBC)
                throw new Exception(String.format("Unsupported CC type %d!", mode));

            /*
            // Pad to 8 bytes
            int len = os.size();
            for (; len % 8 != 0; len++)
                os.write(0);

             */

            return CC(os.toByteArray(), kid, mode);
        }

        private static long CRC32AddTo(long CRC, int byteval) {
            long TabVal;
            int j;
            TabVal = (CRC ^ byteval) & 0xFF;
            for (j = 8; j > 0; j--) {
                if ((TabVal & 1) != 0) TabVal = ((TabVal & 0xffffffffL) >> 1) ^ 0xEDB88320;
                else TabVal = (TabVal & 0xffffffffL) >> 1;
            }
            CRC = (TabVal & 0xffffffffL) ^ (((CRC & 0xffffffffL) >> 8) & 0x00FFFFFF);
            return CRC;
        }

        /**
         * @param b The input
         * @return the 32-bit value
         * @brief perform a cyclic redundancy computation
         */
        private static long CRC32(byte[] b) {
            long CRC = 0xFFFFFFFFL;
            for (int i = 0; i < b.length; i++) {
                int bval = b[i] & 0xFF;
                CRC = CRC32AddTo(CRC, bval);
            }

            CRC ^= 0xFFFFFFFFL;

            CRC &= 0xffffffffL;

            return CRC;
        }

        /**
         * @param in
         * @param key
         * @return
         * @throws Exception
         * @brief Perform a cryptographic checksum
         */
        private static byte[] CC(byte[] in, byte[] key, int mode) throws Exception {


            if (mode != Crypt.AES_CBC && in.length % 8 != 0)
                throw new Exception("Invalid input size. Must be a multiple of 8 bytes");


            if (key.length % 8 != 0) throw new Exception("Invalid key size. Must be a multiple of 8 bytes");

            if (key.length < 8 || key.length > 24)
                throw new Exception("Invalid key size. Must be a multiple of 8, 16 or 24 bytes");
            BlockCipher cipher;
            int finalLen;
            // The cc must be 8 bytes for AES and 4 bytes for all else.
            // Ref Sec 8.2.1.5.1  of ETS TS 102 226 rel 9
            if (mode == Crypt.AES_CBC) {
                finalLen = 8;
                cipher = new AESEngine();
            } else {
                finalLen = 4;
                cipher = key.length == 8 ? new DESEngine() : new DESedeEngine();
            }
            CMac cmac = new CMac(cipher);
            cmac.init(new KeyParameter(key));
            cmac.update(in, 0, in.length);
            byte[] out = new byte[cmac.getMacSize()];
            cmac.doFinal(out, 0);

            return Arrays.copyOf(out, finalLen);
        }


    }

    /**
     * @brief This represents the GSM 03.48 parameters: KIC, KID, TAR, SPI, CNTR and a few other control parameters.
     * They are used when building the OTA packet.
     */
    public static class Params {
        // Encapsulates OTA parameters
        public SecurityDomain sd = null; //!< The security domain targeted
        public ProfileInfo profile = null; //!< Or the targetted profile
        public int kicKeyNum = -1; //!< The kIC index
        public int kidKeyNum = -1; //!< The KID index
        public int spi1 = ServerSettings.getDefault_ota_spi1(); //!< The current SPI1
        public int spi2 = ServerSettings.getDefault_ota_spi2(); //!< The current SPI2
        public boolean forcedSpi1 = false; //!< Whether SPI1 is forced or derived from the KIC/KID
        public boolean forcedSpi2 = false; //!< Whether SPI2 is forced, or derived from configurations
        public int numApdus = 0; //!< The number of command APDUs created/added so far.
        public boolean forceDLR = false;
        public String msisdn = null; //!< The MSISDN
        public Eis eis = null; //!< The EIS entry
        public Long rfmCounter = null; //!< If already bumped, otherwise NULL
        public Long receivedRfmCounter = null; //!< When a MO package is received, this is the parsed RFM counter.
        public boolean allowChaining = false; //!< No script chaining by default. So that we MUST explicitly have it
        // requested for the RFM application
        public boolean forcePush = false;
        public boolean no034bPacking = false; //!< This is used when sending SMS.
        public short responseStatusCode;
        public boolean porOnError = false;
        private byte[] TAR; //!< The TAR. For informational purposes only! If SD is set or profile is set, we use that

        public Params(int spi1, int spi2, int kic, int kid, byte[] tar, byte[] counter, ProfileInfo p,
                      SecurityDomain sd) {
            this.spi1 = spi1;
            this.spi2 = spi2;
            this.kicKeyNum = kic & 0x0f;
            this.kidKeyNum = kid & 0x0f;

            this.TAR = tar;
            this.profile = p;
            this.sd = sd;
            try {
                this.receivedRfmCounter = Utils.BER.decodeInt(counter, 5);
            } catch (Exception ex) {
            }
        }

        public Params(Eis sim, String targetAID, Map<String, Object> params) {
            SecurityDomain sd;
            ProfileInfo p = null;
            if (targetAID == null) // If null, then ISD-R is the target
                sd = sim.findISDR();
            else {
                sd = sim.findSecurityDomainByAID(targetAID); // Else find it by ISD
                if (sd == null) p = sim.findProfileByAID(targetAID); // Else by profile

            }

            Object o;
            try {
                kicKeyNum = (o = params.get("kic")) != null && !Utils.isEmpty(o) ? (int) Utils.toLong(o) : -1;
                kidKeyNum = (o = params.get("kid")) != null && !Utils.isEmpty(o) ? (int) Utils.toLong(o) : -1;
                spi1 = (o = params.get("spi1")) != null && !Utils.isEmpty(o) ? (int) Utils.toLong(o) :
                        ServerSettings.getDefault_ota_spi1();
                forcedSpi1 = !Utils.isEmpty(o); // Track whether it was forced
                spi2 = (o = params.get("spi2")) != null && !Utils.isEmpty(o) ? (int) Utils.toLong(o) :
                        ServerSettings.getDefault_ota_spi2();
                forcedSpi2 = !Utils.isEmpty(o); // Track whether it was forced
                // Get the TAR from the application if set
                if ((o = params.get("tar")) != null) // TAR takes precedence
                    try {
                        setTAR(Utils.HEX.h2b((String) o));
                        if (getTAR().length != 3)
                            throw new Exception(String.format("Invalid TAR length [%d]. Must be 3", getTAR().length));
                        sd = null;
                    } catch (Exception ex) {
                        setTAR(new byte[3]);
                    }
                this.forcePush = Utils.toBool(params.get("force-push")); // Get Force push param
                if (this.forcePush)  // Check for force push: If there, remove it so next round doesn't find it.
                    params.remove("force-push");
            } catch (Exception ex) {
            }


            if (sd != null) {
                this.sd = sd;
                this.eis = sd.getEis();
                this.msisdn = eis.activeMISDN();
                String x = sd.firstTAR();
                setTAR(x);
            }
            this.profile = p;
            if (!forcedSpi1 && sd == null) {
                // Massage SPI1
                if (kicKeyNum >= 0) spi1 |= 0x04;
                if (kidKeyNum >= 0) spi1 |= (spi1 & 0x03) | 0x02; // Turn off all other RC or whatever, Turn on CC
            }

        }

        public Params() {
        } // Empty constructor

        // Grab TAR from profile or SD
        private void updateTarFromSettings() {
            if (this.TAR == null) try {
                String tar = null;
                if (profile != null) tar = profile.TAR();
                else tar = sd.firstTAR();
                this.TAR = Utils.HEX.h2b(tar);
            } catch (Exception ex) {
            }

        }

        public String mkRequestID() {
            // First try with the received counter, else use the generated counter.
            Long x = receivedRfmCounter != null ? receivedRfmCounter : rfmCounter;
            if (x == null) return null;
            return Utils.HEX.b2H(Utils.encodeInteger(x, 5));
        }

        public byte[] getTAR() {
            return TAR;
        }

        public void setTAR(byte[] TAR) {
            this.TAR = TAR;
        }

        public void setTAR(String TAR) {
            setTAR(Utils.HEX.h2b(TAR));
        }

        public String getTARasString() {
            return Utils.HEX.b2H(getTAR());
        }


        public String getHTTPargetApplication() throws Exception {
            String aid;
            if (this.profile != null) aid = this.profile.getIsd_p_aid();
            else if (this.sd != null && this.sd.getRole() != SecurityDomain.Role.ISDR) aid = this.sd.getAid();
            else aid = null;
            return aid == null ? null : Utils.ramHTTPPartIDfromAID(aid);
        }

    }

    /**
     * @brief This class is for general handling Ota responses
     * @details Each class implements a (well) class of OTA response types. The default handles general 03.48-style
     * responses
     * It parses out APDU response codes, maps them correctly (using GSM 11.11 rules), and returns
     * the success or failure of the OTA commands sent
     */
    public static class ResponseHandler {
        protected String name = "Default OTA Response Handler";

        public String getName() {
            return name;
        }

        /**
         * @brief represents a ETSI TS 102 226 or SGP Notification or SendData Response
         */
        public static abstract class RemoteAPDUStructure {
            protected byte[] data;

            private static byte[] getIndefiniteCodingData(InputStream in) throws Exception {
                if (in.read() != 0x80) throw new Exception("Invalid indefinite length coding byte. Must be 0x80");

                // Now get everything up to final '0000'
                byte[] out = new byte[in.available() - 2];
                in.read(out, 0, out.length);
                return out;
            }

            public static RemoteAPDUStructure parse(byte[] data_in) throws Exception {

                // We expect either ETSI TS 102 226 response packet or a generic response
                InputStream input = new ByteArrayInputStream(data_in);
                // Parse it
                int tag = data_in[0] & 0xFF;
                boolean indefiniteCoding =
                        (tag == Response_Scripting_Template_for_Indefinite_Length_Tag || tag == Command_Scripting_Template_for_Indefinite_Length_Tag);
                boolean isResp =
                        (tag == Response_Scripting_Template_Definite_Length_Tag || tag == Response_Scripting_Template_for_Indefinite_Length_Tag);

                RemoteAPDUStructure r;
                // Now parse stuff
                byte[] data;
                if (isResp) {
                    input.read(); // Skip the tag.
                    if (indefiniteCoding) data = getIndefiniteCodingData(input);
                    else { // Else it is definite length coding (Table 5-10) followed # of executed APDUs
                        int len = Utils.BER.decodeTLVLen(input);
                        data = new byte[len];
                        input.read(data);
                        int tag2 = data[0] & 0xFF;
                        if (tag2 == Number_of_Executed_C_APDUS_Tag) {
                            int numApdus = data[2] & 0xFF;
                            // Skip 3 elements as per table 5.11
                            data = Arrays.copyOfRange(data, 3, data.length - 3);
                            Utils.lg.info(String.format("Received response, %d c-apdus executed, data: %s", numApdus,
                                    Utils.HEX.b2H(data)));
                        }
                    }
                    r = new ETSI102226APDUResponses();

                } else {
                    r = new GenericEuiccResponse();
                    data = data_in;
                }
                r.data = data; // Store the data. Might need to parse it. Or might not.
                return r;
            }

            public byte[] getData() {
                return data;
            }

        }

        public static class GenericEuiccResponse extends RemoteAPDUStructure {
            // Just for classing issues...
        }

        public static class ETSI102226APDUResponses extends RemoteAPDUStructure {
            public List<Response> responses = new ArrayList<Response>();

            public static ETSI102226APDUResponses parse(byte[] in) throws Exception {
                return parse(new ByteArrayInputStream(in));
            }


            /**
             * @param xin - The input stream
             * @return
             * @throws Exception
             * @brief parse a sequence of RAPDU or SCP03t responses
             */
            public static ETSI102226APDUResponses parse(InputStream xin) throws Exception {
                byte[] data;
                int tag;

                BufferedInputStream in = new BufferedInputStream(xin);
                ETSI102226APDUResponses r = new ETSI102226APDUResponses();
                while (in.available() > 0) {
                    in.mark(1);
                    int xtag = in.read() & 0xFF;
                    in.reset(); // Put it back
                    // These are the known ETSI tags; look for them
                    if (xtag != 0x23 && xtag != 0x80 && xtag != 0x81 && xtag != 0x83 && xtag != 0x90) {
                        // Copy all to the end
                        data = new byte[in.available()];
                        in.read(data);
                        r.addGenericData(data);
                        break; // We are done
                    }
                    Utils.Pair<InputStream, Integer> res = Utils.BER.decodeTLV(in);
                    data = Utils.getBytes(res.k);
                    tag = res.l;

                    if (tag == R_APDU_TAG) r.add(data);
                    else if (tag == Bad_Format_Tag) r.add(data[0]); // Bad format...
                    else if (tag == Immediate_Action_Response_Tag) r.addImmediateResponse(data);
                    else if (tag != Number_of_Executed_C_APDUS_Tag)
                        r.add(tag, data); // Generic response, e.g. for a SCP03t command
                }

                return r;
            }

            private static String formatError(int porCode, int cmdNum, int sw1, int sw2) {
                if (porCode > 0) {
                    String err = "";
                    switch (porCode) {
                        case 0x01:
                            err = "RC/CC/DS failed";
                            break;
                        case 0x02:
                            err = "RFM Counter is too low";
                            break;
                        case 0x03:
                            err = "RFM Counter is too high";
                            break;
                        case 0x04:
                            err = "RFM Counter is blocked";
                            break;
                        case 0x05:
                            err = "Ciphering error";
                            break;
                        case 0x06:
                            err = "Unidentified security error.";
                            break;
                        case 0x07:
                            err = "Insufficient memory to process incoming message";
                            break;
                        case 0x08:
                            err = "More time needed to process command ";
                            break;
                        case 0x09:
                            err = "Unknown TAR value ";
                            break;
                        default:
                            err = "Unknown reserved RFM/ GSM 03.48 error code";
                            break;
                    }
                    return String.format("%s (%02X)", err, porCode);

                } else return String.format("%s [last cmd #%s]", SDCommand.APDU.euiccError2Str(sw1, sw2), cmdNum);
            }

            /**
             * @param resp the returned data
             * @return {success,retryFlag,FormattedResp}
             * @brief parse response, tell us whether it was a success response or not. Might be over-ridden by
             * sub-classes
             */
            public static Utils.Quad<Boolean, Boolean, String, Ota.ResponseHandler.ETSI102226APDUResponses> examineResponse(byte[] resp) {
                boolean isSuccess = true, retry = false;
                String s = "";
                Ota.ResponseHandler.ETSI102226APDUResponses r = null;
                try {

                    r = parse(resp);
                    Utils.Triple<Boolean, Boolean, String> res = r.process();
                    isSuccess = res.k; // Whether success
                    retry = res.l;
                    s = res.m;
                } catch (Exception ex) {
                }
                return new Utils.Quad<>(isSuccess, retry, s, r);
            }

            public Utils.Triple<Boolean, Boolean, String> process() throws Exception {
                Utils.Quad<Boolean, Boolean, String, byte[]> res = process(new HashMap<>());
                return new Utils.Triple<>(res.k, res.l, res.m);
            }

            /**
             * @return Returns a triple:
             * First element TRUE if this processing was successful
             * Second Element: A retry flag on failure: True if retry should be allowed/done
             * Third element: The formatted result or null
             * @throws Exception
             * @brief Process an OTA expanded response, picking out success or fail:
             */

            private Utils.Quad<Boolean, Boolean, String, byte[]> process(Map<Integer, Utils.Pair<Boolean, String>> resultsMap) {
                ETSI102226APDUResponses r = this;
                String frmt = "";
                ByteArrayOutputStream os = new ByteArrayOutputStream(); // Record output

                String sep = "";
                boolean hasError = false;
                int ct = 0;

                for (Response rp : r.responses)
                    if (rp.type == Response.ResponseType.BadFormat) {
                        String err;
                        switch (rp.sw1) { // Sec 5.2.2 of ETSI TS 102 226
                            case 1:
                                err = "Unknown TAG";
                                break;
                            case 2:
                                err = "Wrong length found";
                                break;
                            case 3:
                                err = "Length not found";
                                break;
                            default:
                                err = String.format("Error %s", rp.sw1);
                                break;
                        }
                        String xs = String.format("%sError in command [%s]", sep, err);
                        frmt += xs;
                        hasError = true;
                        sep = ", ";
                        resultsMap.put(ct, new Utils.Pair<Boolean, String>(false, xs));
                        ct++;
                    } else if (rp.type == Response.ResponseType.Immediate_Action_Response) try {
                        frmt = String.format("%sProactive sim Response [%s]", sep, Utils.HEX.b2H(rp.data));
                        sep = ", ";
                        os.write(rp.data);
                    } catch (Exception ex) {
                    }
                    else if (rp.type == Response.ResponseType.RAPDU) try {
                        // Response proper
                        boolean isSuccess = SDCommand.APDU.isSuccessCode(rp.sw1);

                        String xs = String.format("%s[Cmd<%s> <%s>", sep, formatError(0, ct, rp.sw1, rp.sw2),
                                rp.data.length > 0 ? Utils.HEX.b2H(rp.data) : "(no resp data)");
                        frmt += xs;
                        hasError |= !isSuccess; // Any error is treated as a total failure. Right?
                        sep = ", ";
                        // Store in results map
                        resultsMap.put(ct, new Utils.Pair<Boolean, String>(isSuccess, xs));
                        os.write(rp.data); // Record response data
                        // Write SW1 + SW2 on end
                        os.write(new byte[]{(byte) rp.sw1, (byte) rp.sw2}); // XX make sure upper layers are aware of
                        // this!
                        ct++;
                    } catch (Exception ex) {
                    }
                    else if (rp.type == Response.ResponseType.GenericTLV) {
                        // This is always taken is not error (let receiver handle)
                        frmt += String.format("%s[Generic Resp <tag = %02x, data: %s>]", rp.tag,
                                Utils.HEX.b2H(rp.data));
                        try {
                            Utils.BER.appendTLV(os, (short) rp.tag, rp.data); // Copy and return what was sent as-is
                            //  os.write(rp.data);
                        } catch (Exception e) {
                        }
                    } // Ignore data

                return new Utils.Quad<Boolean, Boolean, String, byte[]>(!hasError, false, frmt, os.toByteArray());
            }

            public void add(byte[] data) {
                int sw1 = data[data.length - 2] & 0xFF;
                int sw2 = data[data.length - 1] & 0xFF;
                int dlen = data.length;
                byte[] rdata = new byte[dlen - 2 >= 0 ? dlen - 2 : 0];
                System.arraycopy(data, 0, rdata, 0, rdata.length);
                responses.add(new Response(sw1, sw2, rdata));
            }

            public void add(int errorcode) {
                responses.add(new Response(errorcode));
            }

            public void add(int tag, byte[] data) {
                responses.add(new Response(tag, data));
            }

            public void addImmediateResponse(byte[] data) {
                responses.add(new Response(data));
            }

            public void addGenericData(byte[] data) {
                responses.add(new Response(Response.ResponseType.GenericData, data));
            }

            public static class Response {
                public ResponseType type;

                public int tag;
                public int sw1;
                public int sw2;
                public byte[] data;

                public Response(int sw1, int sw2, byte[] resp) {
                    this.sw1 = sw1;
                    this.sw2 = sw2;
                    this.data = resp;
                    this.type = ResponseType.RAPDU;
                }

                public Response(int errorType) {
                    this.sw1 = errorType;
                    this.type = ResponseType.BadFormat;
                }

                public Response(byte[] actionResponse) {
                    this.type = ResponseType.Immediate_Action_Response;
                    this.data = actionResponse;
                }

                public Response(int tag, byte[] data) {
                    this.tag = tag;
                    this.data = data;
                    this.type = ResponseType.GenericTLV;
                }

                public Response(ResponseType type, byte[] data) {
                    this.type = type;
                    this.data = data;
                    this.tag = -1;
                }

                public enum ResponseType {BadFormat, Immediate_Action_Response, RAPDU, GenericTLV, GenericData}
            }
        }
    }
}

/**
 * @}
 */