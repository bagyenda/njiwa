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

package io.njiwa.common;

import io.njiwa.common.model.KeyComponent;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.BigIntegers;

import javax.crypto.KeyAgreement;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.cert.Extension;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;

/**
 * Created by bagyenda on 07/12/2016.
 */
public class ECKeyAgreementEG {

    // Table 23 of SGP 02 v3.1
    public static final byte[] EUM_DEFAULT_DISCRETIONARY_DATA = new byte[]{(byte) 0xC0};
    public static final byte[] CI_DEFAULT_DISCRETIONARY_DATA = new byte[]{(byte) 0x00};
    // As per Table 76 of SGP 02 v3.1
    public static final byte[] SM_DP_DEFAULT_DISCRETIONARY_DATA = new byte[]{(byte) 0xC8, 0x01, 0x01};
    public static final byte[] SM_SR_DEFAULT_DISCRETIONARY_DATA = new byte[]{(byte) 0xC8, 0x01, 0x02};

    public static final byte INCLUDE_DERIVATION_RANDOM = 0x02;
    public static final byte CERTIFICATE_VERIFICATION_PRECEDES = 0x8;
    public static final int KEY_QUAL_ONE_KEY = 0x5c;
    public static final int KEY_QUAL_THREE_KEYS = 0x10;

    public static  final byte[] DST_VERIFY_KEY_TYPE = new byte[] {(byte)0x82};  // Table 11-17 of GPC
    public static  final byte[] KEY_AGREEMENT_KEY_TYPE = new byte[] {0, (byte)0x80}; // Table 3-5 of GPC Ammend. E
    // See https://stackoverflow.com/questions/17877412/how-to-prove-that-one-certificate-is-issuer-of-another-certificates
    private static final String SUBJECT_KEY_IDENTIFIER_OID = "2.5.29.14";
    private static final String AUTHORITY_KEY_IDENTIFIER_OID = "2.5.29.35";
    public static final int SM_SR_CERTIFICATE_TYPE = 0x02; // Table 39 of SGP.02 v4.1
    public static final int SM_DP_CERTIFICATE_TYPE = 0x01; // Table 77 of SGP.02 v4.1
    public static final byte[] GPC_A_CERTIFICATE_TAG = {(byte) 0x7F, (byte) 0x21};
    public static final byte[] GPC_A_SIGNATURE_TAG = {(byte) 0x5F, (byte) 0x37};
    public static final byte[] SGP02_CERTIFICATE_OF_OFFCARD_ENTITY_TAG = {(byte) 0x3A, (byte) 0x01};
    public static final byte[] SGP02_KEY_ESTABLISHMENT_TAG = {0x3A, 0x02};
    public static final byte[] SGP02_PUBLIC_KEY_TAG = {0x7F, 0x49};
    public static final byte[] GPC_A_SUBJECT_IDENTIFIER_TAG = {0x5F, 0x20};
    public static final byte[] GPC_A_CERT_EFFECTIVE_DATE_TAG = {0x5F, 0x25};
    public static final byte[] GPC_A_CERT_EXPIRY_DATE_TAG = {0x5F, 0x24};
    
    //1. To generate the ephemeral keys, we We follow this (except for the KDF bit): https://neilmadden.wordpress
    // .com/2016/05/20/ephemeral-elliptic-curve-diffie-hellman-key-agreement-in-java/
    //2. To generate the Shared secret, use http://grepcode.com/file/repo1.maven.org/maven2/org
    // .bouncycastle/bcprov-jdk15/1.45/org/bouncycastle/crypto/agreement/ECDHCBasicAgreement.java?av=f supplying the
    // public and private key
    //3. Convert the BigInteger to a octetstring using: http://stackoverflow.com/questions/18819095/how-insert-bits-into-block-in-java-cryptography
    // Where size = log_base_256 of the number. To get the size (i.e. log) we use: log_256 x = (log_2 x) / (log_2
    // 256) and: https://www.borelly.net/cb/docs/javaBC-1.4.8/prov/org/bouncycastle/pqc/math/linearalgebra/IntegerFunctions.html
    //4. For the KDF, basically it is enough to do a SHA256(ZAB | counter | [SharedInfo]) because the KDF in TS 03111
    // has a loop that is never entered because ceil(k/l) is always 1. Then take left-most X bytes as required for
    // key len. (Counter is 32bit big-endian value of 1)

    // OR: Use ECDH to generate the secret, then use above KDF observation to generate the KDF

    static {
        // Add Bouncy Castle
        Security.addProvider(new BouncyCastleProvider());
    }


    public static byte[] getCertificateSubjectKeyIdentifier(X509Certificate cert)
    {
        // According to https://stackoverflow.com/questions/6523081/why-doesnt-my-key-identifier-match#6529052
        // It is always 20 bytes, so we expect 04 LEN 04 LEN2 DATA
        try {
            byte[] o = cert.getExtensionValue(SUBJECT_KEY_IDENTIFIER_OID);
            return Arrays.copyOfRange(o,4,o.length);
        } catch (Exception ex) {
            String xs = ex.getMessage();
        }
        return null;
    }

    public static byte[] getCertificateAuthorityKeyIdentifier(X509Certificate cert)
    {
        byte[] o = cert.getExtensionValue(AUTHORITY_KEY_IDENTIFIER_OID);
        ASN1OctetString oc = ASN1OctetString.getInstance(o);
        AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(oc.getOctets());
        return aki.getKeyIdentifier();
    }

    // ECKA-DH and ECKA-EG are basically the same except for the two-way exchange of public keys between A (sender)
    // and B (receiver), and the use on the other side of the other public key.
    // See Sec 4.3.1 of BSI TR-03111
    public static byte[] genZAB(PrivateKey ourPk, PublicKey otherPubkey) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(ourPk);
        ka.doPhase(otherPubkey, true);

        byte[] zab = ka.generateSecret();

        return zab;
    }

    /**
     * @brief Generate keyData as per Sec 4.3.3 of BSI TS 03111
     * @param zab
     * @param sharedInfo
     * @param keyDataLengthBits
     * @return
     * @throws Exception
     */
    public static byte[] x963KDF(byte[] zab, byte[] sharedInfo, int keyDataLengthBits) throws Exception {
        // Big-endian 32-bit integer value "1"
        byte[] counter = new byte[]{
                0, 0, 0, 1
        };
        int ctr = 1;
        final int L = 256; // The hash length;
        int J = (keyDataLengthBits + L - 1)/L; // The ceil value, see
        MessageDigest hash = MessageDigest.getInstance("SHA-256"); // As per spec
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        for (int i = 1; i<=J; i++) {
            hash.update(zab);
            hash.update(Utils.encodeInteger(ctr, 4));
            if (sharedInfo != null)
                hash.update(sharedInfo);
            byte[] digest = hash.digest();
            os.write(digest);
            ctr++;
            hash.reset();
        }

        return os.toByteArray();

    }

    public static SDCommand.APDU isdpKeySetEstablishmentINSTALLCmd(String aid) {
        final byte[] xaid = Utils.HEX.h2b(aid);
        ByteArrayOutputStream os = new ByteArrayOutputStream() {
            {
                try {
                    write(new byte[]{0, 0, (byte) xaid.length}); // Sec 4.1.3.1 of SGP doc
                    write(xaid);
                    write(new byte[]{0, 0, 0});
                } catch (Exception ex) {
                }
            }
        };
        return new SDCommand.APDU(0x80, 0xE6, 0x20, 0x00, os.toByteArray());
    }

    public static SDCommand.APDU isdKeySetEstablishmentSendCert(byte[] signedCert) throws Exception {

        return new SDCommand.APDU(0x80, 0xE2, 0x09, 0x00, new ByteArrayOutputStream() {
            {
                Utils.BER.appendTLV(this, SGP02_CERTIFICATE_OF_OFFCARD_ENTITY_TAG, signedCert);
            }
        }.toByteArray()); // XXX Might be a long command.
    }

    /**
     * @brief: Make the send certificate data. According to GPC Ammendment A Sec 3.3.2, the dat must be TLV encoded.
     * @param cert
     * @param certificate_type
     * @param discretionaryData
     * @param sig
     * @return
     * @throws Exception
     */
    public static SDCommand.APDU isdKeySetEstablishmentSendCert(X509Certificate cert, int certificate_type, byte[] discretionaryData, final byte[] sig)
            throws Exception {
        // Make the data: Table 77 of SGP.02 v4.1
        final byte[] sigdata = makeCertSigningData(cert, certificate_type, discretionaryData,  KEY_AGREEMENT_KEY_TYPE);

        final byte[] certData = new ByteArrayOutputStream() {
            {
                write(sigdata);
                Utils.BER.appendTLV(this, GPC_A_SIGNATURE_TAG, sig);
            }
        }.toByteArray();

        // Make top-level
        final byte[] xdata = new ByteArrayOutputStream() {
            {
                Utils.BER.appendTLV(this, GPC_A_CERTIFICATE_TAG,certData);
            }
        }.toByteArray();

        return isdKeySetEstablishmentSendCert(xdata);
    }

    public static byte[] makeA6CRT(final int numkeys,
                                   final byte[] sdin,
                                   final byte[] hostID,
                                   int keyID, int keyVersion, int scenarioParam) throws Exception {
        return makeA6CRT(numkeys, sdin, hostID, keyID, keyVersion, new byte[0], null,
                KeyComponent.Type.AES, 16,
                scenarioParam);
    }

    public static byte[] makeA6CRT(final int numkeys,
                                   final byte[] sdin,
                                   final byte[] hostID,
                                   int keyID, int keyVersion,
                                   byte[] initialCounter,
                                   Byte keyAccess,
                                   KeyComponent.Type keyType,
                                   int keyLen,
                                   int scenarioParam) throws Exception {

        return new ByteArrayOutputStream() {
            {
                Utils.BER.appendTLV(this, (short) 0xA6,
                        new ByteArrayOutputStream() {
                            {
                                write(new byte[]{
                                        (byte) 0x90,
                                        0x02,
                                        0x03, // Scenario #3
                                        // Include DR in key derivation, delete existing keys, include sdin/sin if
                                        // passed
                                        (byte) (scenarioParam |
                                                // Whether SDIN and so on is included.
                                                ((sdin != null && hostID != null) ? 0x4 : 0)),
                                });
                                write(new byte[]{(byte) 0x95, 0x01, (byte) (numkeys == 1 ? KEY_QUAL_ONE_KEY : KEY_QUAL_THREE_KEYS)});
                                // One/three secure
                                if (keyAccess != null)
                                    write(new byte[]{(byte) 0x96, 0x01, keyAccess});
                                // channel key
                                write(new byte[]{(byte) 0x80, 0x01, (byte) keyType.toInt()}); // AES key
                                write(new byte[]{(byte) 0x81, 0x01, (byte) keyLen}); // Key length
                                write(new byte[]{(byte) 0x82, 0x01, (byte) keyID}); // Key Identifier (for first key)
                                write(new byte[]{(byte) 0x83, 0x01, (byte) keyVersion}); // Key version
                                if (initialCounter == null)
                                    write(new byte[]{(byte) 0x91, 0x00,}); // Initial counter = 0
                                else
                                    Utils.BER.appendTLV(this, (short) 0x91, initialCounter); // Better beof length 0, 2,03,05 or 08
                                if (sdin != null && hostID != null) {
                                    Utils.BER.appendTLV(this, (short) 0x45, sdin);
                                    Utils.BER.appendTLV(this, (short) 0x84, hostID);
                                }
                            }
                        }.toByteArray());
            }
        }.toByteArray();
    }

    /**
     * @param dr
     * @return
     * @throws Exception
     * @brief Compute the receipt as per Table 4-22 of GPC Ammendment E
     */
    public static byte[] computeReceipt(final byte[] dr, byte[] sdin, byte[] hostID, int keyID, int keyVersion,
                                        int scenarioParam,
                                        byte[] receiptKey)
            throws Exception {
        byte[] data = new ByteArrayOutputStream() {
            {
                write(makeA6CRT(1, sdin, hostID, keyID, keyVersion, scenarioParam));
                if (dr != null)
                    Utils.BER.appendTLV(this, (short) 0x85, dr);
            }
        }.toByteArray();
        return Utils.aesMAC(data, receiptKey);
    }

    /**
     * @param keyUsageQual
     * @param dr
     * @param hostID
     * @param sdin
     * @param sin
     * @return
     * @throws Exception
     * @brief Compute Shared Info according to GPC Ammend. A
     */
    public static byte[] computeSharedInfo(int keyUsageQual, final byte[] dr, byte[] hostID, byte[] sdin, byte[] sin)
            throws
            Exception {
        // Table 3-28 of GPC Ammendment A
        return new ByteArrayOutputStream() {
            {
                write(keyUsageQual); // One key
                write(KeyComponent.Type.AES.toInt()); //  Type = AES
                write(16); // 16 byte key
                if (dr != null)
                    write(dr);
                if (hostID != null) {
                    Utils.BER.appendTLVlen(this, hostID.length);
                    write(hostID);
                }
                if (sdin != null && sin != null) {
                    Utils.BER.appendTLVlen(this, sin.length);
                    write(sin);
                    Utils.BER.appendTLVlen(this, sdin.length);
                    write(sdin);
                }
            }
        }.toByteArray();
    }

    /**
     * @param dr
     * @return
     * @throws Exception
     * @brief compute key data according to table 4.3 of BSI TR 03111 (as Initiator
     */
    public static byte[] computeKeyData(int keyQual, byte[] dr, byte[] hostID, byte[] sdin, byte[] sin,
                                        byte[] ecasd_pubkey, int ecasd_pubkey_paramRef, byte[] eSK,
                                        int keyDataLenBits) throws
            Exception {
        byte[] sharedInfo = ECKeyAgreementEG.computeSharedInfo(keyQual, dr, hostID, sdin, sin);
        ECPublicKey ecasdPubKey = Utils.ECC.decodePublicKey(ecasd_pubkey, ecasd_pubkey_paramRef);
        ECPrivateKey eSKDPECKA = Utils.ECC.decodePrivateKey(eSK, ecasd_pubkey_paramRef);
        byte[] zab = ECKeyAgreementEG.genZAB(eSKDPECKA, ecasdPubKey);
        return x963KDF(zab, sharedInfo, keyDataLenBits);
    }

    public static byte[] computeKeyData(int keyQual, byte[] dr, byte[] hostID, byte[] sdin, byte[] sin,
                                        byte[] ecasd_pubkey, int ecasd_pubkey_paramRef, byte[] eSK) throws Exception
    {
        return computeKeyData(keyQual,dr,hostID,sdin,sin,ecasd_pubkey,ecasd_pubkey_paramRef,eSK,256);
    }

    public static SDCommand.APDU isdKeySetEstablishmentSendKeyParams(byte[] randomChallenge,
                                                                     final KeyPair
                                                                             ephemeralKeys,
                                                                     final byte[] a6crt, int keyRef) throws
            Exception {
        byte[] ePk = Utils.ECC.encode((ECPublicKey) ephemeralKeys.getPublic(), keyRef);
        //Make the signable object, Table 81 or SGP v3.1
        ByteArrayOutputStream os = new ByteArrayOutputStream() {
            {
                Utils.BER.appendTLV(this, SGP02_KEY_ESTABLISHMENT_TAG, a6crt);
                Utils.BER.appendTLV(this, SGP02_PUBLIC_KEY_TAG, ePk);
            }
        };
        // Make signing data and sign it
        Utils.BER.appendTLV(os,  new byte[] { 0x00, (byte)0x85}, randomChallenge);
        final byte[] sig = Utils.ECC.sign((ECPrivateKey) ephemeralKeys.getPrivate(), os.toByteArray());
        return isdKeySetEstablishmentSendKeyParams(ePk, a6crt, sig);
    }

    public static SDCommand.APDU isdKeySetEstablishmentSendKeyParams(byte[] ePk, byte[]
            a6crt, byte[] sig)
            throws Exception {
        byte[] tdata = new ByteArrayOutputStream() {
            {
                Utils.BER.appendTLV(this, SGP02_KEY_ESTABLISHMENT_TAG, a6crt);
                Utils.BER.appendTLV(this, SGP02_PUBLIC_KEY_TAG, ePk);
                Utils.BER.appendTLV(this, GPC_A_SIGNATURE_TAG, sig);
            }
        }.toByteArray();
        return new SDCommand.APDU(0x80, 0xE2, 0x89, 0x01, tdata);
    }

    public static byte[] makeCertSigningData(final X509Certificate cert,
                                             int certificateType,
                                             byte[] additionaldiscretionaryDataTLVs,
                                             /* byte keyParamRef,  */
                                             byte[] keyUsageQual) throws Exception {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        // Key paramRef must come from ECpublickey
        byte keyParamRef = (byte)Utils.ECC.getKeyParamRefFromCertificate(cert);
        // Table 77 of SGP 02 v3.1
        byte[] cSerial = BigIntegers.asUnsignedByteArray(cert.getSerialNumber());
        Utils.BER.appendTLV(os, (short) 0x93, cSerial);
        // Sec 2.3.2.2 of SGP 02 v4.1 says that the following should be the "Authority Key Identifier"
        byte[] caid =  getCertificateAuthorityKeyIdentifier(cert); // cert.getExtensionValue(AUTHORITY_KEY_IDENTIFIER_OID);
        Utils.BER.appendTLV(os, (short) 0x42, caid);

        byte[] subjectIdentifier = getCertificateSubjectKeyIdentifier(cert); // cert.getExtensionValue(SUBJECT_KEY_IDENTIFIER_OID);
        Utils.BER.appendTLV(os, GPC_A_SUBJECT_IDENTIFIER_TAG, subjectIdentifier);
        Utils.BER.appendTLV(os, (byte) 0x95, keyUsageQual);
        Date startDate = cert.getNotBefore();
        Date expDate = cert.getNotAfter();

        SimpleDateFormat df = new SimpleDateFormat("yyyMMdd");
        if (startDate != null)
            Utils.BER.appendTLV(os, GPC_A_CERT_EFFECTIVE_DATE_TAG,
                    Utils.HEX.h2b(df.format(startDate)));
        Utils.BER.appendTLV(os,  GPC_A_CERT_EXPIRY_DATE_TAG,
                Utils.HEX.h2b(df.format(expDate)));
        // Make the discretionary data:
        // Table 77 of SGP 02 v4.1 & XX shows it should have:
        // C8 01 cert_type (01 = SM-DP, 02 = SM-SR
        // C9 {L} authority_key_identifier
        // Other TLVs
        ByteArrayOutputStream dd = new ByteArrayOutputStream() {{
           Utils.BER.appendTLV(this,(short)0xC8, new byte[] {(byte)certificateType});
           Utils.BER.appendTLV(this,(short)0xC9, caid);
           if (additionaldiscretionaryDataTLVs != null)
               this.write(additionaldiscretionaryDataTLVs);
        }};
        Utils.BER.appendTLV(os, (short) 0x73, dd.toByteArray());

        // Do Public Key
        ECPublicKey ecPublicKey = (ECPublicKey) cert.getPublicKey();
        byte[] xpubData = Utils.ECC.encode(ecPublicKey, keyParamRef);

        Utils.BER.appendTLV(os, SGP02_PUBLIC_KEY_TAG, xpubData);
        return os.toByteArray();
    }

    public static byte[] genCertificateSignature(PrivateKey key, final X509Certificate cert, int certificate_type, byte[] discretionaryData, byte[] keyUsageQual)
            throws Exception {
        // Generate a certificate signature
        byte[] os = makeCertSigningData(cert, certificate_type, discretionaryData, keyUsageQual);
        return genCertificateSignature(key, os);
    }

    public static byte[] genCertificateSignature(PrivateKey key, byte[] certSigData) throws Exception {
        return Utils.ECC.sign((ECPrivateKey) key, certSigData);
    }

}
