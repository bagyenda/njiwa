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

package io.njiwa.dp.transactions;

import io.njiwa.common.ECKeyAgreementEG;
import io.njiwa.common.Utils;
import io.njiwa.common.model.RpaEntity;
import io.njiwa.common.model.TransactionType;
import io.njiwa.common.ws.WSUtils;
import io.njiwa.common.ws.types.BaseResponseType;
import io.njiwa.common.ws.types.BaseTransactionType;
import io.njiwa.common.ws.types.WsaEndPointReference;
import io.njiwa.dp.Scp03;
import io.njiwa.dp.model.Euicc;
import io.njiwa.dp.model.ProfileTemplate;
import io.njiwa.dp.model.SmDpTransaction;
import io.njiwa.dp.ws.ES2Client;
import io.njiwa.common.SDCommand;
import io.njiwa.dp.model.ISDP;
import io.njiwa.dp.pedefinitions.EUICCResponse;
import io.njiwa.sr.ws.interfaces.ES3;
import io.njiwa.sr.ws.types.*;

import javax.persistence.EntityManager;
import javax.xml.ws.Holder;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedDeque;

/**
 * @brief Represents a downloadProfile transactions (see Sec 5.3.2 of SGP 02 v3.1
 */
public class DownloadProfileTransaction extends BaseTransactionType implements Scp03.GetKey,
        ProfileTemplate.ConnectivityParams {
    public static final byte SCP03_KEY_VERSION = 0x03;
    public static final byte SCP03_KEY_ID = 0x01;
    private static final int MAXIMUM_PROFILE_SEGMENT_LENGTH = 512;
    public Stage currentStage;
    public long eUICCId = -1;
    public String eid;
    public boolean enableProfile;
    public byte[] profileTLVs;
    public int offset; // Offset into profileTLVs
    public long smsrId; // The ID of the SM-SR
    public byte[] randomChallenge; // Random challenge returned by the card...
    public byte[] hostID; // Our generated host ID
    public byte[] sdin;
    public byte[] sin;
    public byte[] ecasd_pubkey;
    public int ecasd_pubkey_paramRef;
    public byte[] secureChannelBaseKey;
    public byte[] receiptKey;
    public String iccid; // Profile ICCID
    // The ephemeral  keys
    public byte[] eSK_DP_ECKA, ePK_DP_ECKA;
    public ConcurrentLinkedDeque<Scp03.Session> scp03Sessions;
    public String imsi;
    public String msisdn;
    public Pol2Type pol2;

    public DownloadProfileTransaction() {
    }

    public DownloadProfileTransaction(EntityManager em, ProfileTemplate template,
                                      Euicc euicc,
                                      long smsrId, boolean
                                              enable) throws
            Exception {
        currentStage = Stage.CREATEISDP;
        enableProfile = enable;
        this.smsrId = smsrId;

        // Try and get profile data
        profileTLVs = template.performDataPreparation(em, euicc.getEid(), this);
        if (profileTLVs == null)
            throw new Exception("Invalid: Failed to prepare profile data");


        try {
            sdin = Utils.HEX.h2b(euicc.getEcasd_sdin());
            sin = Utils.HEX.h2b(euicc.getEcasd_sin());
        } catch (Exception ex) {
            sdin = null;
            sin = null;
        }
        hostID = new byte[16];
        new SecureRandom().nextBytes(hostID); // Grab some random bytes
        ecasd_pubkey = euicc.getEcasd_public_key_q(); // Store keys...
        ecasd_pubkey_paramRef = euicc.getEcasd_public_key_param_ref();
        iccid = template.getIccid();
        scp03Sessions = new ConcurrentLinkedDeque<>();
        eUICCId = euicc.getId();
        eid = euicc.getEid();
    }

    private void setChannelAndReceiptKeys(byte[] dr) throws Exception {
        byte[] keyData = ECKeyAgreementEG.computeKeyData(0x5C, dr, hostID, sdin, sin, ecasd_pubkey, ecasd_pubkey_paramRef,
                eSK_DP_ECKA, 256
        );
        // According to Table 3-29 of GPC Ammendment A, the receipt key gets first 16 bytes, and securee channel
        // base key next 16 bytes, so:

        secureChannelBaseKey = new byte[16];
        receiptKey = new byte[16];
        System.arraycopy(keyData, 0, receiptKey, 0, receiptKey.length);
        System.arraycopy(keyData, receiptKey.length, secureChannelBaseKey, 0, secureChannelBaseKey.length);
    }

    @Override
    protected synchronized void processResponse(EntityManager em, long tid, TransactionType.ResponseType responseType, String reqId,
                                                byte[] response) {
        boolean hasError = false;
        String cmdType;
        SmDpTransaction trans = em.find(SmDpTransaction.class, tid);
        switch (currentStage) {
            case CREATEISDP:
                boolean isSuccess = responseType != TransactionType.ResponseType.SUCCESS;
                cmdType = "CreateISDP";
                if (responseType == TransactionType.ResponseType.SUCCESS) {
                    // Check return code
                    try {
                        // Parse response as RAPDU
                        Utils.Pair<Integer, byte[]> xres = Utils.BER.decodeTLV(response);
                        byte[] resp = xres.l;
                        // Get response code
                        int sw1 = resp[resp.length - 2];
                        //  int sw2 = resp[resp.length-1];
                        isSuccess = SDCommand.APDU.isSuccessCode(sw1);
                    } catch (Exception ex) {
                        isSuccess = false;
                    }
                }

                if (!isSuccess) { // Inform MNO
                    status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                            new BaseResponseType.ExecutionStatus.StatusCode("8.4", "4.2", "Execution error",
                                    "execution error"));
                    ES2Client.sendDownloadProfileResponse(em, status,
                            getReplyToAddress(em, "ES2"),
                            originallyTo, requestingEntityId, response, relatesTO, startDate, iccid);

                }

                // else Mark as created..., was done by upper layer. Right?
                break;
            case ESTABLISHKEYSET_SEND_CERT_DP_ECDSA:
                cmdType = "EstablishISDPKeySet";
                if (responseType != TransactionType.ResponseType.SUCCESS) {
                    status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                            new BaseResponseType.ExecutionStatus.StatusCode("8.4", "4.2", "Execution error",
                                    "execution error"));
                    ES2Client.sendDownloadProfileResponse(em, status,
                            getReplyToAddress(em, "ES2"),
                            originallyTo, requestingEntityId,response, relatesTO, startDate, iccid);
                } else try {
                    List<Utils.Pair<Integer, byte[]>> l = Utils.BER.decodeTLVs(response);
                    // Look over them. First non-success code means error, first one with data and TAG = 85 =
                    // RandomChallenge, so record it.
                    for (Utils.Pair<Integer, byte[]> x : l) {
                        byte[] resp = x.l;
                        int sw1 = resp[resp.length - 2];
                        //   int sw2 = resp[resp.length-1];

                        if (!SDCommand.APDU.isSuccessCode(sw1))
                            hasError = true;
                        else if (resp.length > 2) {
                            // Get the challenge
                            byte[] xresp = new byte[resp.length - 2];
                            System.arraycopy(resp, 0, xresp, 0, xresp.length);
                            // Decode as TLV with tag = 85
                            Utils.Pair<Integer, byte[]> y = Utils.BER.decodeTLV(xresp);
                            if (y.k == 0x85)
                                randomChallenge = y.l; // Record randomChallenge
                        }
                    }
                } catch (Exception ex) {
                    hasError = true;
                }
                if (hasError || randomChallenge == null) {
                    status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                            new BaseResponseType.ExecutionStatus.StatusCode("8.4", "4.2", "Execution error",
                                    "execution error"));
                    ES2Client.sendDownloadProfileResponse(em, status,
                            getReplyToAddress(em, "ES2"),
                            originallyTo,requestingEntityId, response, relatesTO, startDate, iccid);
                }
                break;
            case ESTABLISHKEYSET_SEND_DP_ECKA:
                cmdType = "EstablishISDPKeySet";
                if (responseType != TransactionType.ResponseType.SUCCESS) {
                    status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                            new BaseResponseType.ExecutionStatus.StatusCode("8.4", "4.2", "Execution error",
                                    "execution error"));
                    ES2Client.sendDownloadProfileResponse(em, status,
                            getReplyToAddress(em, "ES2"),
                            originallyTo, requestingEntityId,response, relatesTO, startDate, iccid);
                } else try {
                    byte[] DR = null;
                    byte[] receipt = null;
                    List<Utils.Pair<Integer, byte[]>> l = Utils.BER.decodeTLVs(response);
                    // Look for DR and receipt
                    for (Utils.Pair<Integer, byte[]> x : l) {
                        byte[] resp = x.l;
                        int sw1 = resp[resp.length - 2];
                        //   int sw2 = resp[resp.length-1];

                        if (!SDCommand.APDU.isSuccessCode(sw1))
                            hasError = true;
                        else if (resp.length > 2) {
                            // Get the challenge
                            byte[] xresp = new byte[resp.length - 2];
                            System.arraycopy(resp, 0, xresp, 0, xresp.length);
                            // Decode as TLV with tag = 85 or 86
                            ByteArrayInputStream in = new ByteArrayInputStream(xresp);
                            while (in.available() > 0) {
                                Utils.Pair<InputStream, Integer> y = Utils.BER.decodeTLV(in);
                                byte[] xdata = Utils.getBytes(y.k);
                                if (y.l == 0x85)
                                    DR = xdata; // Record DR
                                else if (y.l == 0x86)
                                    receipt = xdata;
                            }
                        }
                    }
                    if (receipt == null || hasError) {
                        status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                                new BaseResponseType.ExecutionStatus.StatusCode("8.4", "4.2", "Execution error",
                                        "execution error"));
                        ES2Client.sendDownloadProfileResponse(em, status,
                                getReplyToAddress(em, "ES2"),
                                originallyTo,requestingEntityId, response, relatesTO, startDate, iccid);
                    } else {
                        setChannelAndReceiptKeys(DR);
                        byte[] xreceipt = ECKeyAgreementEG. computeReceipt(DR,sdin,hostID,SCP03_KEY_ID,
                                SCP03_KEY_VERSION,ECKeyAgreementEG.INCLUDE_DERIVATION_RANDOM|ECKeyAgreementEG
                                        .CERTIFICATE_VERIFICATION_PRECEDES,
                                receiptKey); // Check
                        // receipt
                        if (!Arrays.equals(xreceipt, receipt)) {
                            status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                                    new BaseResponseType.ExecutionStatus.StatusCode("8.4", "4.2", "Execution error",
                                            "execution error"));
                            ES2Client.sendDownloadProfileResponse(em, status,
                                    getReplyToAddress(em, "ES2"),
                                    originallyTo, requestingEntityId,response, relatesTO, startDate, iccid);
                            hasError = true;
                        }
                    }
                } catch (Exception ex) {
                    hasError = true;
                }
                break;
            case DOWNLOADPROFILE:
                cmdType = "DownloadProfile";
                if (responseType != TransactionType.ResponseType.SUCCESS) {
                    status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                            new BaseResponseType.ExecutionStatus.StatusCode("8.4", "4.2", "Execution error",
                                    "execution error"));
                    ES2Client.sendDownloadProfileResponse(em, status,
                            getReplyToAddress(em, "ES2"),
                            originallyTo,requestingEntityId, response, relatesTO, startDate, iccid);
                } else try {
                    // Handle response, one by one
                    ByteArrayInputStream xin = new ByteArrayInputStream(response);
                    BufferedInputStream in = new BufferedInputStream(xin);
                    Scp03.Session session = null;
                    while (in.available() > 0) {
                        in.mark(1);
                        int xtag = in.read();
                        in.reset();

                        if (xtag == 0x9F) {
                            // We have an error!
                            status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                                    new BaseResponseType.ExecutionStatus.StatusCode("8.4", "4.2", "Execution error",
                                            "execution error"));
                            ES2Client.sendDownloadProfileResponse(em, status,
                                    getReplyToAddress(em, "ES2"),
                                    originallyTo,requestingEntityId, response, relatesTO, startDate, iccid);

                            hasError = true;
                            break;
                        }
                        // Rebuild the TLV and pass to response handler
                        final Utils.Pair<InputStream, Integer> xres = Utils.BER.decodeTLV(in);
                        byte[] xresp = new ByteArrayOutputStream() {
                            {
                                byte[] data = Utils.getBytes(xres.k);
                                Utils.BER.appendTLV(this, (short) (int) xres.l, data);
                            }
                        }.toByteArray();
                        session = scp03Sessions.pollFirst(); // Get session
                        byte[] resp = session.processResponse(xresp, this);
                        if (resp != null && resp.length > 0) {
                            String xs = "", sep = "";
                            // Process Profile TLV command responses
                            ByteArrayInputStream derInput = new ByteArrayInputStream(resp);
                            while (derInput.available() > 0)
                                try {
                                    EUICCResponse euiccResponse = new EUICCResponse();
                                    euiccResponse.decode(derInput, true); // XXX assume implicit coding. Right?
                                    Utils.Pair<Boolean, String> pRes = ProfileTemplate.processEuiccResponse
                                            (euiccResponse);
                                    hasError |= pRes.k; // Has errors if one has errors
                                    xs += sep + pRes.l;
                                    sep = "; ";
                                } catch (Exception ex) {
                                }
                            try {
                                // Record parsed response
                                trans.recordResponse(em, "DownloadAndInstallProfile", xs, !hasError);
                            } catch (Exception ex) {
                            }
                        }

                    }
                    if (session != null)
                        scp03Sessions.addLast(session.copyOf()); // Put back what we got last. Right?
                    if (hasError) {
                        status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                                new BaseResponseType.ExecutionStatus.StatusCode("8.4", "4.2", "Execution error",
                                        "execution error"));
                        ES2Client.sendDownloadProfileResponse(em, status,
                                getReplyToAddress(em, "ES2"),
                                originallyTo,requestingEntityId, response, relatesTO, startDate, iccid);
                    } else {
                        ISDP isdp = trans.getIsdp();
                        isdp.setState(ISDP.State.Disabled); // Installed but not enabled.
                        if (!enableProfile)
                            status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus
                                    .Status.ExecutedSuccess);
                        else
                            status = null;
                    }
                    if (status != null) // All done. Send MNO a response
                        ES2Client.sendDownloadProfileResponse(em, status,
                                getReplyToAddress(em, "ES2"),
                                originallyTo, requestingEntityId,response, relatesTO, startDate, iccid);
                } catch (Exception ex) {
                    Utils.lg.severe("Error handling downloadProfile response: " + ex.getMessage());
                }
                break;
            case ENABLEPROFILE:
                boolean success = responseType != TransactionType.ResponseType.SUCCESS;
                cmdType = "EnableISDP";
                if (responseType == TransactionType.ResponseType.SUCCESS) {
                    // Check return code
                    try {
                        // Parse response as RAPDU
                        Utils.Pair<Integer, byte[]> xres = Utils.BER.decodeTLV(response);
                        byte[] resp = xres.l;
                        // Get response code
                        int sw1 = resp[resp.length - 2];
                        //  int sw2 = resp[resp.length-1];
                        success = SDCommand.APDU.isSuccessCode(sw1);
                    } catch (Exception ex) {
                        success = false;
                    }
                }
                if (!success)
                    status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                            new BaseResponseType.ExecutionStatus.StatusCode("8.4", "4.2", "Execution error",
                                    "execution error"));
                else {
                    // Mark it enabled
                    ISDP isdp = trans.getIsdp();
                    isdp.setState(ISDP.State.Enabled);
                    status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status
                            .ExecutedSuccess);
                }
                ES2Client.sendDownloadProfileResponse(em, status,
                        getReplyToAddress(em, "ES2"),
                        originallyTo,requestingEntityId, response, relatesTO, startDate, iccid); // Always inform MNO
                break;
            default:
                cmdType = currentStage.name();
                break;
        }
        trans.recordResponse(em, cmdType, Utils.HEX.b2H(response), !hasError); // Record response.
        if (responseType == TransactionType.ResponseType.SUCCESS && !hasError) {
            // go to next status
            currentStage = currentStage.next();
        } else
            currentStage = Stage.ERROR;

        if (currentStage == Stage.ERROR) {
            SmDpTransaction tr = em.find(SmDpTransaction.class, tid);
            tr.setStatus(SmDpTransaction.Status.Error); // Right?
        }
    }

    // We must over-ride how hasMore works...
    @Override
    public boolean hasMore() {
        switch (currentStage) {
            case DOWNLOADPROFILE:
                return (offset < profileTLVs.length || enableProfile);
            // If we have finished but must enable it, then say so
            case COMPLETE:
            case ERROR:
                return false;
            default:
                return true;
        }
    }

    private boolean doSendData(EntityManager em, byte[] data, SmDpTransaction trans) {
        try {
             RpaEntity smsr = em.find(RpaEntity.class, smsrId);

            final WsaEndPointReference rcptTo = new WsaEndPointReference(smsr,"ES3");
            final String toAddress = rcptTo.makeAddress();
            final ES3 proxy = WSUtils.getPort("http://namespaces.gsma.org/esim-messaging/1", "ES3Port",
                    rcptTo, ES3.class,
                    RpaEntity.Type.SMDP, em,requestingEntityId);
            WsaEndPointReference sender = new WsaEndPointReference(RpaEntity.getLocal(RpaEntity.Type.SMDP),"ES3");
            final Holder<String> msgType = new Holder<String>("http://gsma" +
                    ".com/ES3/ProfileManagement/ES3-CreateISDP");
            String msgID = trans.newRequestMessageID(); // Create new one.
            String aid = trans.getIsdp().getAid(); // Get AID
            SendDataResponse resp = proxy.sendData(sender, toAddress, null, msgID, msgType, msgID,
                    TransactionType.DEFAULT_VALIDITY_PERIOD, eid, aid,
                    Utils
                            .HEX.b2H(data), true, null);
            if (resp != null &&
                    resp.functionExecutionStatus.status != BaseResponseType.ExecutionStatus.Status.ExecutedSuccess)
                throw new Exception("Execution failed: " + resp);
        } catch (WSUtils.SuppressClientWSRequest wsa) {
            return false;
        } catch (Exception ex) {
            Utils.lg.severe("Failed to issue sendData  call: " + ex.getMessage
                    ());
        }
        return false;
    }

    @Override
    public Object sendTransaction(EntityManager em, Object tr) throws Exception {
        final SmDpTransaction trans = (SmDpTransaction) tr; // Grab the transaction
        final ISDP isdp = trans.getIsdp();
// Send stuff...
        switch (currentStage) {
            case CREATEISDP:

                try {
                     RpaEntity smsr = em.find(RpaEntity.class, smsrId);

                    final WsaEndPointReference rcptTo = new WsaEndPointReference(smsr,"ES3");
                    final String toAddress = rcptTo.makeAddress();
                    final ES3 proxy = WSUtils.getPort("http://namespaces.gsma.org/esim-messaging/1", "ES3Port",
                            rcptTo, ES3.class,
                            RpaEntity.Type.SMDP, em,requestingEntityId);
                    WsaEndPointReference sender = new WsaEndPointReference(RpaEntity.getLocal(RpaEntity.Type.SMDP),
                            "ES3");
                    final Holder<String> msgType = new Holder<String>("http://gsma" +
                            ".com/ES3/ProfileManagement/ES3-CreateISDP");
                    String msgID = trans.newRequestMessageID(); // Create new one.
                    ProfileTemplate profileTemplate = isdp.getProfileTemplate();
                    String mnoOID = isdp.getMno_oid();
                    em.flush(); // XXX Right?
                    CreateISDPResponse resp = proxy.createISDP(sender, toAddress, null, msgID, msgType, msgID,
                            TransactionType.DEFAULT_VALIDITY_PERIOD, isdp.getEuicc()
                                    .getEid(), isdp.getIccid(), mnoOID, profileTemplate.getRequiredMemory(), true, null);
                    if (resp != null &&
                            resp.functionExecutionStatus.status != BaseResponseType.ExecutionStatus.Status.ExecutedSuccess)
                        throw new Exception("Execution failed: " + resp);
                    return true;
                } catch (WSUtils.SuppressClientWSRequest wsa) {
                    return true;
                } catch (Exception ex) {
                    Utils.lg.severe("Failed to issue async createisdp call: " + ex.getMessage());
                }
                break;
            case ESTABLISHKEYSET_SEND_CERT_DP_ECDSA:
                // Sec 4.1.3.1 of SGP 02 v3.1
                final SDCommand.APDU inst_p = ECKeyAgreementEG.isdpKeySetEstablishmentINSTALLCmd(isdp.getAid());
                RpaEntity smdp = RpaEntity.getLocal(RpaEntity.Type.SMDP);


                final SDCommand.APDU store_data_p = ECKeyAgreementEG.isdKeySetEstablishmentSendCert(smdp
                                .secureMessagingCert(),
                        ECKeyAgreementEG.SM_DP_CERTIFICATE_TYPE,
                        smdp.getAdditionalDiscretionaryData(), smdp.getSignature());
                // Make data
                ByteArrayOutputStream os = new ByteArrayOutputStream() {
                    {
                        write(inst_p.toByteArray());
                        write(store_data_p.toByteArray());
                    }
                };
                byte[] data = os.toByteArray();

                return doSendData(em, data, trans);


            case ESTABLISHKEYSET_SEND_DP_ECKA:
                // Make  ephemeral keys
                KeyPair kp = Utils.ECC.genKeyPair(ecasd_pubkey_paramRef);
                ePK_DP_ECKA = Utils.ECC.encode((ECPublicKey) kp.getPublic());
                eSK_DP_ECKA = Utils.ECC.encode((ECPrivateKey) kp.getPrivate());
                byte[] a6 = ECKeyAgreementEG.makeA6CRT(1, sdin, hostID, SCP03_KEY_ID, SCP03_KEY_VERSION,
                        ECKeyAgreementEG.INCLUDE_DERIVATION_RANDOM|ECKeyAgreementEG.CERTIFICATE_VERIFICATION_PRECEDES);
                final SDCommand apdu = ECKeyAgreementEG.isdKeySetEstablishmentSendKeyParams(randomChallenge, kp,
                        a6,ecasd_pubkey_paramRef);
                try {
                    return doSendData(em, apdu.toByteArray(), trans);
                } catch (Exception ex) {
                    return false;
                }
            case DOWNLOADPROFILE:
                // First look for a session
                Scp03.Session session = scp03Sessions.pollFirst();
                if (session == null || session.state == Scp03.Session.State.DEAD)
                    // Make new session
                    session = new Scp03.Session(Scp03.Session.Mode.TLV, SCP03_KEY_VERSION, SCP03_KEY_ID);

                final List<SDCommand> l = new ArrayList<>(); // The commands to be sent
                // We have to send INITIALISE or EXTERNAL_AUTH
                if (session.state != Scp03.Session.State.AUTHENTICATED) {
                    l.add(session.scp03Command());
                    scp03Sessions.addLast(session.copyOf()); // Store session
                } else {
                    // Break up the profile TLVs, send them, save the sub-sessions since they have the saved info
                    InputStream in = new ByteArrayInputStream(profileTLVs);
                    while (in.available() > 0) {
                        int dlen = Math.min(in.available(), MAXIMUM_PROFILE_SEGMENT_LENGTH);
                        byte[] pData = new byte[dlen];
                        in.read(pData);
                        SDCommand c = session.scp03Command(SDCommand.SCP03tCommand.ProfileElement
                                (pData));
                        l.add(c);
                        scp03Sessions.addLast(session.copyOf());
                    }
                }
                try {
                    // Send the data
                    byte[] xdata = new ByteArrayOutputStream() {
                        {
                            for (SDCommand c : l)
                                write(c.toByteArray());
                        }
                    }.toByteArray();
                    boolean res = doSendData(em, xdata, trans);
                    offset = profileTLVs.length; // End of. Right?
                    return res;
                } catch (Exception ex) {
                }
                return true;
            case PROFILEDOWNLOADCOMPLETE: // Indicate done, move to next...
                try {
                    final RpaEntity smsr = em.find(RpaEntity.class, smsrId);

                    final WsaEndPointReference rcptTo = new WsaEndPointReference(smsr,"ES3");
                    final String toAddress = rcptTo.makeAddress();
                    final ES3 proxy = WSUtils.getPort("http://namespaces.gsma.org/esim-messaging/1", "ES3Port",
                            rcptTo, ES3.class,
                            RpaEntity.Type.SMDP, em,requestingEntityId);
                    WsaEndPointReference sender = new WsaEndPointReference(RpaEntity.getLocal(RpaEntity.Type.SMDP),
                            "ES3");
                    final Holder<String> msgType = new Holder<String>("http://gsma" +
                            ".com/ES3/ProfileManagement/ES3-ProfileDownloadCompletedRequest");
                    String iccid = isdp.getIccid();
                    ProfileTemplate profileTemplate = isdp.getProfileTemplate();
                    String profType = profileTemplate.getType();
                    SubscriptionAddress address = new SubscriptionAddress();
                    String msgID = trans
                            .newRequestMessageID();
                    address.imsi = this.imsi;
                    address.msisdn = this.msisdn;
                    BaseResponseType resp = proxy.profileDownloadCompleted(sender, toAddress, null,
                            msgID, msgType, msgID, TransactionType.DEFAULT_VALIDITY_PERIOD, isdp.getEuicc().getEid(),
                            iccid, profType, address, pol2);
                    boolean isSuccess = (resp != null &&
                            resp.functionExecutionStatus.status == BaseResponseType.ExecutionStatus.Status
                                    .ExecutedSuccess);

                    trans.recordResponse(em, "ProfiledownloadComplete", resp.toString(), isSuccess);
                    if (!isSuccess)
                        throw new Exception("Execution failed: " + resp);
                    currentStage = Stage.ENABLEPROFILE; // Skip to next
                    return true;
                } catch (Exception ex) {
                }
                return false;
            case ENABLEPROFILE:
                if (!enableProfile) {
                    currentStage = Stage.COMPLETE;
                    return true;
                } else {
                    try {
                        final RpaEntity smsr = em.find(RpaEntity.class, smsrId);

                        final WsaEndPointReference rcptTo = new WsaEndPointReference(smsr,"ES3");
                        final String toAddress = rcptTo.makeAddress();
                        final ES3 proxy = WSUtils.getPort("http://namespaces.gsma.org/esim-messaging/1", "ES3Port",
                                rcptTo, ES3.class,
                                RpaEntity.Type.SMDP, em,requestingEntityId);
                        WsaEndPointReference sender = new WsaEndPointReference(RpaEntity.getLocal(RpaEntity.Type
                                .SMDP),
                                "ES3");
                        final Holder<String> msgType = new Holder<String>("http://gsma" +
                                ".com/ES3/ProfileManagement/ES3-EnableISDP");
                        String msgID = trans.newRequestMessageID(); // Create new one.
                        String iccid = isdp.getIccid();
                        EnableProfileResponse resp = proxy.enableProfile(sender, toAddress, null, msgID, msgType,
                                msgID,
                                TransactionType.DEFAULT_VALIDITY_PERIOD,
                                isdp.getEuicc().getEid(), iccid, null);
                        if (resp != null &&
                                resp.functionExecutionStatus.status != BaseResponseType.ExecutionStatus.Status.ExecutedSuccess)
                            throw new Exception("Execution failed: " + resp);
                        return true;
                    } catch (WSUtils.SuppressClientWSRequest wsa) {
                    } catch (Exception ex) {
                        Utils.lg.severe("Failed to issue async enable isdp call: " + ex.getMessage());
                        return false;
                    }
                    return true;
                }
        }

        return false;
    }

    @Override
    public byte[] getAESkey(int keyVersion, int keyID) {
        return secureChannelBaseKey; // Return base key
    }

    @Override
    public void set(String imsi, String msisdn, Pol2Type pol2) {
        this.msisdn = msisdn;
        this.imsi = imsi;
        this.pol2 = pol2;
    }

    public enum Stage {
        CREATEISDP, ESTABLISHKEYSET_SEND_CERT_DP_ECDSA, ESTABLISHKEYSET_SEND_DP_ECKA,
        DOWNLOADPROFILE, PROFILEDOWNLOADCOMPLETE, ENABLEPROFILE, COMPLETE, ERROR;

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
