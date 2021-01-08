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

package io.njiwa.sr.transactions;

import io.njiwa.common.model.Key;
import io.njiwa.common.model.RpaEntity;
import io.njiwa.common.model.TransactionType;
import io.njiwa.common.ECKeyAgreementEG;
import io.njiwa.common.SDCommand;
import io.njiwa.common.Utils;
import io.njiwa.common.model.KeyComponent;
import io.njiwa.common.model.KeySet;
import io.njiwa.common.ws.types.BaseResponseType;
import io.njiwa.common.ws.types.WsaEndPointReference;
import io.njiwa.sr.model.AuditTrail;
import io.njiwa.sr.model.ProfileInfo;
import io.njiwa.sr.model.SecurityDomain;
import io.njiwa.sr.model.SmSrTransaction;
import io.njiwa.sr.ota.Ota;
import io.njiwa.sr.transports.Transport;
import io.njiwa.sr.ws.ES2Client;
import io.njiwa.sr.ws.ES4Client;
import io.njiwa.sr.ws.ES7Impl;
import io.njiwa.sr.ws.types.Eis;

import javax.persistence.EntityManager;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.*;

/**
 * Created by bagyenda on 09/05/2017.
 */
public class ReceiveEISHandoverTransaction extends SmSrBaseTransaction {
    public String mnoID;
    public Stage stage;
    public Eis eis;
    public long eisId;
    public byte[] pk_ecasd_ecka;
    public int pk_ecasd_param;

    public byte[] ePk_sr_ecka;
    public byte[] eSk_sr_ecka;
    public int ePk_ecka_param;

    public byte[] randomChallenge;
    public byte[] hostID;
    public int scenarioParam;
    public int keyVersion;
    public byte[] dr;
    public byte[] receipt;
    public byte[] receiptKey;
    public byte[] kic;
    public byte[] kid;
    public byte[] sdin;
    public byte[] sin;
    public String oldSmsR;
    public int eccLength;

    public ReceiveEISHandoverTransaction() {
    }

    public ReceiveEISHandoverTransaction(String mnoID) {
        this.mnoID = mnoID;
        this.stage = Stage.START;
        kic = new byte[16];
        kid = new byte[16];
        receiptKey = new byte[16];
    }

    @Override
    protected synchronized void processResponse(EntityManager em, long tid, ResponseType responseType, String reqId) {
        SmSrTransaction tr = em.find(SmSrTransaction.class, tid);
        boolean hasError = false;
        Ota.ResponseHandler.ETSI102226APDUResponses.Response r = findFirstRAPDU();
        byte[] resp = r.data;
        if (status == null) {
            if (responseType == TransactionType.ResponseType.EXPIRED)
                status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Expired,
                        new BaseResponseType.ExecutionStatus.StatusCode("1.6", "", "5.3", "Expired"));
            else if (responseType == TransactionType.ResponseType.SUCCESS)
                status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status
                        .ExecutedSuccess, new BaseResponseType.ExecutionStatus.StatusCode("8.7", "", "1.1", ""));
            else
                status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status
                        .Failed, new BaseResponseType.ExecutionStatus.StatusCode("8.7", "", "1.1", ""));
        }

        switch (stage) {
            case START:
                RpaEntity mno = RpaEntity.getByOID(em, mnoID, RpaEntity.Type.MNO);
                ES4Client.sendPrepareSMSChangeResponse(em, status, new WsaEndPointReference(mno, "ES4"),
                        originallyTo, requestingEntityId,
                        relatesTO,
                        startDate);
                break;
            case AUTHENTICATESMSR:
                randomChallenge = resp;
                tr.markReadyToSend(); // Force out.

                break;
            case CREATEKEYSET:
                int drLen = eccLength <= 383 ? 16 : eccLength <= 511 ? 24 : 32; // Table 3-27 GPC Ammend A
                dr = new byte[drLen];
                receipt = new byte[16];
                // Copy back
                System.arraycopy(resp, 0, receipt, 0, receipt.length);
                System.arraycopy(resp, receipt.length, dr, 0, dr.length);
                try {
                    byte[] keyData = ECKeyAgreementEG.computeKeyData(ECKeyAgreementEG.KEY_QUAL_THREE_KEYS, // As per Sec 5.6.1 of SGP 02
                            // v3.1
                            dr, hostID, sdin, sin, pk_ecasd_ecka, ePk_ecka_param, eSk_sr_ecka, 512);
                    System.arraycopy(keyData, 0, receiptKey, 0, receiptKey.length);
                    System.arraycopy(keyData, receiptKey.length, kic, 0, kic.length);
                    System.arraycopy(keyData, receiptKey.length + kic.length, kid, 0, kid.length);
                    // XXX we assume other side set key ID for first key to 1
                    byte[] xreceipt = ECKeyAgreementEG.computeReceipt(dr, sdin, hostID, 1, keyVersion,
                            scenarioParam,
                            receiptKey);
                    hasError = !Arrays.equals(xreceipt, receipt);
                    if (!hasError) {
                        // Save the EIS. Right?
                        io.njiwa.sr.model.Eis xeis = eis.toModel();
                        if (xeis == null)
                            throw new Exception("Failed to parse EIS");
                        xeis.setRegistrationComplete(false);

                        SecurityDomain isdr = xeis.findISDR();
                        // Patch it with our new keys.
                        List<KeySet> l = isdr.getKeysets();
                        if (l == null) {
                            l = new ArrayList<>();

                        } else {
                            // Remove all other keysets XXX ?
                            List<KeySet> xl = new ArrayList<>();
                            try {
                                for (KeySet k : l)
                                    if (k.getType() != KeySet.Type.SCP80 && k.getType() != KeySet.Type.SCP81 &&
                                            k.getType() != KeySet.Type.SCP03)
                                        xl.add(k);
                                l = xl;
                            } catch (Exception ex) {
                            }
                        }
                        List<Key> keyList = Arrays.asList(new Key(Key.KIC_KEY_IDENTIFIER,
                                new KeyComponent(kic, KeyComponent.Type.AES)),
                                new Key(Key.KID_KEY_IDENTIFIER,
                                        new KeyComponent(kid, KeyComponent.Type.AES)));
                        l.add(new KeySet(keyVersion, KeySet.Type.SCP80, new ArrayList<>(), keyList, 1L));
                        isdr.setKeysets(l);
                        xeis.setOldSmsRId(oldSmsR); // Store old SMSR. Right?
                        em.persist(xeis); // Save it
                        eisId = xeis.getId();
                        tr.setEis_id(xeis.getId()); // Grab the ID as well, add it to our transaction
                    }
                } catch (Exception ex) {
                    hasError = true;
                }

                break;
            case FINALISEHANDOVER:
                // Ignore errors. Right? Simply move to complete
                io.njiwa.sr.model.Eis eis;
                try {
                    eis = em.find(io.njiwa.sr.model.Eis.class, eisId);
                    eis.setRegistrationComplete(true); // Mark as fully registered
                } catch (Exception ex) {
                    eis = null;
                }
                if (status == null)
                    status =  new BaseResponseType.ExecutionStatus(
                            responseType == TransactionType.ResponseType.SUCCESS ? BaseResponseType.ExecutionStatus.Status.ExecutedSuccess :
                                    BaseResponseType.ExecutionStatus.Status.Failed,
                            new BaseResponseType.ExecutionStatus.StatusCode("8.4", "", "4.2", ""));
                AuditTrail.addAuditTrail(em, tid, AuditTrail.OperationType.FinaliseISDRhandover, status, null, null,
                        null, null);
                // Make new SCP81 keys...
                try {
                    CreateSCP81KeySet trObj = new CreateSCP81KeySet(eis);
                    SmSrTransaction xtr = new SmSrTransaction(em, "CreateSCP81Keys", "createSCP81keys", null, eis.getEid
                            (), DEFAULT_VALIDITY_PERIOD, false, trObj);
                    em.persist(xtr);
                } catch (Exception ex) {
                    Utils.lg.severe(String.format("Failed to start transaction for creating EIS keys: %s", ex));
                }
                RpaEntity smsr = RpaEntity.getByOID(em, oldSmsR, RpaEntity.Type.SMSR);
                ES7Impl.ES7Client.sendHandoverEUICCResponse(em, status, new WsaEndPointReference(smsr,
                                "ES7"), originallyTo,requestingEntityId, relatesTO,
                        startDate);
                // Notify all SM-DP and MNOs...
                // We do this in current thread, and hope for the best...
                Date endDate = Calendar.getInstance().getTime();
                try {
                    RpaEntity rpa;
                    for (ProfileInfo p : eis.getProfiles()) {
                        String mnoID = p.getMno_id();
                        String smdpId = p.getSmdpOID();
                        if (mnoID != null && (rpa = RpaEntity.getByOID(em, mnoID, RpaEntity.Type.MNO)) != null) {
                            // Call the MNO
                            ES2Client.sendSMSRChangeNotification(em, new WsaEndPointReference(rpa, "ES2"),
                                    requestingEntityId,
                                    null, null, eis, endDate);
                        } else if (smdpId != null && (rpa = RpaEntity.getByOID(em, smdpId, RpaEntity.Type.SMDP)) !=
                                null)
                            ES4Client.sendSMSRChangeNotification(em, new WsaEndPointReference(rpa, "ES4"),
                                    null, requestingEntityId, null,  eis, endDate);
                    }
                } catch (Exception ex) {
                }

                break;
            default:
                hasError = false;
                break;
        }
        if (!hasError)
            stage = stage.next();
    }

    @Override
    public Object sendTransaction(EntityManager em,
                                  Object xtr) throws Exception {
        SmSrTransaction tr = (SmSrTransaction) xtr;
        Date tnow = Calendar.getInstance().getTime();
        Date expirest = tr != null ? tr.getExpires() : tnow;
        long expirySecs = expirest.getTime() - tnow.getTime();
        switch (stage) {
            case START: // Nothing to do
                return true;
            case AUTHENTICATESMSR:
                try {
                    // Get our RPA Entity and Data
                    RpaEntity smsr = RpaEntity.getLocal(RpaEntity.Type.SMSR);
                    X509Certificate cert = smsr.secureMessagingCert();
                    // Make cert data
                    byte[] certSigningData = ECKeyAgreementEG.makeCertSigningData(cert,
                            ECKeyAgreementEG.SM_SR_CERTIFICATE_TYPE,
                            smsr.getAdditionalDiscretionaryData(),
                             ECKeyAgreementEG.KEY_AGREEMENT_KEY_TYPE);
                    String eid = eis.signedInfo.eid;
                    tr.setMsisdn(eid); // Fake it. For now
                    String msgId = tr.genMessageIDForTrans(em);
                    BaseResponseType r = ES7Impl.ES7Client.sendAuthenticateSMSR(em, getReplyToAddress(em, "ES7"),
                            originallyTo, requestingEntityId, msgId, eis
                                    .signedInfo.eid,
                            certSigningData);
                    Utils.Triple<Integer, Transport.MessageStatus,
                            Utils.Triple<Long, String, Transport.TransportType>> sres = new Utils.Triple<>(0,
                            BaseResponseType.toMessageStatus(r, Transport.MessageStatus.Sent),
                            new Utils.Triple<>(expirySecs, "", Transport.TransportType.WS));
                    return sres;
                } catch (Exception ex) {
                }
                return false;
            case CREATEKEYSET:
                hostID = new byte[16];
                new SecureRandom().nextBytes(hostID); // Make host ID
                try {
                    // Get SIN and SDIN
                    sdin = Utils.HEX.h2b(eis.isdR.sdin);
                    sin = Utils.HEX.h2b(eis.isdR.sin);
                } catch (Exception ex) {
                }
                int useSDIN = sdin != null && sin != null ? 0x04 : 0x00;
                scenarioParam = (ECKeyAgreementEG.INCLUDE_DERIVATION_RANDOM | useSDIN | ECKeyAgreementEG.CERTIFICATE_VERIFICATION_PRECEDES); //
                // Include DR | Include
                // HostID, | Cert
                // Verification
                // precedes key Establishment
                // Choose a key version
                // We will create SCP80 keys. So:
                Utils.Pair<Integer, Integer> verLimits = KeySet.Type.SCP80.versionLimits();
                keyVersion = verLimits.k; // Grab our key param
                try {
                    int max = 0;
                    for (Eis.SecurityDomain.KeySet k : eis.isdR.keySets)
                        if (k.type == Eis.SecurityDomain.KeySet.Type.SCP80 && k.version != null && k.versionAsInt() > max)
                            max = k.versionAsInt();
                    if (max < verLimits.l)
                        keyVersion = max + 1;
                    else
                        scenarioParam |= 0x01; // Delete existing
                } catch (Exception ex) {
                }
                RpaEntity smsr = RpaEntity.getLocal(RpaEntity.Type.SMSR);
                ECPrivateKey privateKey = smsr.secureMessagingPrivKey();
                X509Certificate certificate = smsr.secureMessagingCert();
                int paramSpec = Utils.ECC.getKeyParamRefFromCertificate(certificate);
                KeyPair pair = Utils.ECC.genKeyPair(paramSpec);
                ePk_ecka_param = paramSpec; // Store it.
                ePk_sr_ecka = Utils.ECC.encode((ECPublicKey) pair.getPublic(), paramSpec); // Include param spec when
                // sending it
                eSk_sr_ecka = Utils.ECC.encode((ECPrivateKey) pair.getPrivate()); // Store both
                byte[] cert = ECKeyAgreementEG.makeCertSigningData(smsr.secureMessagingCert(), ECKeyAgreementEG.SM_SR_CERTIFICATE_TYPE,
                        smsr.getAdditionalDiscretionaryData(),
                        ECKeyAgreementEG.KEY_AGREEMENT_KEY_TYPE);
                byte[] signature = ECKeyAgreementEG.genCertificateSignature(privateKey, cert);
                eccLength = Utils.ECC.keyLength((ECPublicKey) pair.getPublic());
                String eccKeyLength = String.format("ECC-%d", eccLength);
                String msgId = tr.genMessageIDForTrans(em);
                String eid = eis.signedInfo.eid;
                BaseResponseType r = ES7Impl.ES7Client.sendCreateAdditionalKeySet(em, getReplyToAddress(em, "ES7"), originallyTo,
                        requestingEntityId,
                        msgId, eid, keyVersion, 1, eccKeyLength, scenarioParam, hostID, ePk_sr_ecka, signature);

                Utils.Triple<Integer, Transport.MessageStatus,
                        Utils.Triple<Long, String, Transport.TransportType>> sres = new Utils.Triple<>(0,
                        BaseResponseType.toMessageStatus(r, Transport.MessageStatus.Sent),
                        new Utils.Triple<>(expirySecs, "", Transport.TransportType.WS));
                return sres;

            case FINALISEHANDOVER:
                // Section 4.1.1.9 of SGP v3.1
                SDCommand.APDU apdu = new SDCommand.APDU(0x80, 0xE4, 00, 00, new byte[]{
                        (byte) 0xF2,
                        0x03,
                        (byte) keyVersion,
                        0x01, // First to last key ID
                        0x03
                });
                cAPDUs = new ArrayList<>();
                addAPDU(apdu); // Add the APDU
                // Then call super send
                return super.sendTransaction(em, tr);
            default:
                return null;
        }
    }

    @Override
    public boolean hasMore() {
        switch (stage) {
            default:
                return false;
            case START:
            case VERIFYECASD:
            case AUTHENTICATESMSR:
            case CREATEKEYSET:
                return true; // XX right??
            case FINALISEHANDOVER:
                return super.hasMore(); // Uses regular stuff
        }
    }

    public enum Stage {
        ERROR, START, VERIFYECASD, AUTHENTICATESMSR, CREATEKEYSET, FINALISEHANDOVER, COMPLETE;

        private static Stage[] vals = values();

        public Stage next() {
            if (this == COMPLETE)
                return COMPLETE;
            else if (this == ERROR)
                return ERROR;
            else
                // From: http://stackoverflow.com/questions/17006239/whats-the-best-way-to-implement-next-and-previous-on-an-enum-type
                return vals[(this.ordinal() + 1) % vals.length];
        }
    }
}
