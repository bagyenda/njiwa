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

import io.njiwa.common.Utils;
import io.njiwa.common.model.Key;
import io.njiwa.common.model.KeyComponent;
import io.njiwa.common.model.RpaEntity;
import io.njiwa.common.ws.types.WsaEndPointReference;
import io.njiwa.common.ECKeyAgreementEG;
import io.njiwa.common.SDCommand;
import io.njiwa.common.ws.types.BaseResponseType;
import io.njiwa.sr.model.AuditTrail;
import io.njiwa.sr.model.Eis;
import io.njiwa.sr.model.SmSrTransaction;
import io.njiwa.sr.ota.Ota;
import io.njiwa.sr.transports.Transport;
import io.njiwa.sr.ws.ES7Impl;

import javax.persistence.EntityManager;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Calendar;
import java.util.Date;

/**
 * Created by bagyenda on 18/05/2017.
 */
public class EISHandoverTransaction extends SmSrBaseTransaction {
    public String mnoID;
    public long targetSMSr;
    public long eid_id;
    public Stage stage;
    public byte[] smsrCert;
    public byte[] hostID;
    public byte[] ePk;
    public int scenarioParam;
    public int eccLength;
    public byte[] signature;
    public int sequenceNumber;
    public int keyVersionNumber;

    public EISHandoverTransaction() {

    }

    public EISHandoverTransaction(String mnoID, long targetSMSr, long eid_id) {
        this.mnoID = mnoID;
        this.targetSMSr = targetSMSr;
        this.eid_id = eid_id;
        stage = Stage.HANDOVER_EUICC;
    }

    @Override
    protected synchronized void processResponse(EntityManager em, long tid, ResponseType responseType, String reqId) {
        SmSrTransaction tr = em.find(SmSrTransaction.class, tid);
        boolean hasError = !(responseType == ResponseType.SUCCESS);

        Ota.ResponseHandler.ETSI102226APDUResponses.Response rapdu = findFirstRAPDU();
        byte[] resp = rapdu.data;
        switch (stage) {
            case HANDOVER_EUICC:
                // We expect the certificate
                if (!hasError)
                    try {
                        smsrCert = resp;
                        // Certificate already verified...
                        tr.markReadyToSend(); // Since it is waiting for expiry, tell it to go out right away
                    } catch (Exception ex) {
                    }
                break;
            case AUTHENTICATE_SMSR:
                try {
                    BaseResponseType.ExecutionStatus status = hasError ? null :
                            new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status
                                    .ExecutedSuccess);
                    RpaEntity sender = em.find(RpaEntity.class, targetSMSr);
                    tr.setNextSend(Utils.infiniteDate); // Don't let it go out...
                    ES7Impl.ES7Client.sendAuthenticateSMSRresponse(em, status,
                            new WsaEndPointReference(sender, "ES7"), originallyTo,requestingEntityId, relatesTO, startDate,
                            hasError ? null : resp);
                } catch (Exception ex) {
                    Utils.lg.severe(String.format("Failed to issue AuthenticateSMSR reply: %s", ex));
                }
                break;
            case CREATE_ADDITIONAL_KEYSET:
                try {

                    BaseResponseType.ExecutionStatus status;
                    byte[] receipt = null;
                    byte[] dr = null;
                    ByteArrayInputStream in = new ByteArrayInputStream(resp);
                    if (!hasError) {
                        while (in.available() > 0) {
                            Utils.Pair<InputStream, Integer> out = Utils.BER.decodeTLV(in);
                            byte[] data = Utils.getBytes(out.k);
                            if (out.l == 0x85)
                                dr = data;
                            else if (out.l == 0x86)
                                receipt = data;
                        }
                        status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status
                                .ExecutedSuccess);
                    } else
                        status = null;
                    RpaEntity sender = em.find(RpaEntity.class, targetSMSr);
                    tr.setNextSend(Utils.infiniteDate); // Don't let it go out...

                        BaseResponseType.ExecutionStatus     xstatus =  new BaseResponseType.ExecutionStatus(
                                responseType == ResponseType.SUCCESS ? BaseResponseType.ExecutionStatus.Status.ExecutedSuccess :
                                        BaseResponseType.ExecutionStatus.Status.Failed,
                                new BaseResponseType.ExecutionStatus.StatusCode("8.4", "", "4.2", ""));
                    AuditTrail.addAuditTrail(em, tid, AuditTrail.OperationType.EstablishISDRkeyset, xstatus, null,
                            null, null,
                            null);
                    ES7Impl.ES7Client.sendcreateAdditionalKeySetResponse(em, status, new WsaEndPointReference(sender,
                            "ES7"), originallyTo,requestingEntityId, relatesTO, startDate, receipt, dr);
                } catch (Exception ex) {
                    Utils.lg.severe(String.format("Failed to issue createAdditionalKeyset reply: %s", ex));
                }
                break;

        }

        if (!hasError)
            stage = stage.next();
        else
            stage = Stage.ERROR;
    }

    @Override
    public Object sendTransaction(EntityManager em,
                                  Object xtr) throws Exception {
        SmSrTransaction tr = (SmSrTransaction) xtr;
        Date tnow = Calendar.getInstance().getTime();
        Date expirest = tr != null ? tr.getExpires() : tnow;
        long expirySecs = expirest.getTime() - tnow.getTime();

        switch (stage) {
            case HANDOVER_EUICC:
                // call HandOver euicc...
                try {
                    Eis eis = tr.eisEntry(em);
                    String msgId = tr.genMessageIDForTrans(em);
                    boolean res = ES7Impl.ES7Client.sendHandoverEUICC(em, getReplyToAddress(em, "ES7"), originallyTo,
                            requestingEntityId,
                            msgId, msgId, eis);
                    Utils.Triple<Integer, Transport.MessageStatus,
                            Utils.Triple<Long, String, Transport.TransportType>> sres = new Utils.Triple<>(0,
                            res ? Transport.MessageStatus.Sent : Transport.MessageStatus.SendFailedFatal,
                            new Utils.Triple<>(expirySecs, "", Transport.TransportType.WS)); // Don't send it again,
                    // set next send to expiry time
                    return sres;
                } catch (Exception ex) {
                }

                return false;
            case AUTHENTICATE_SMSR:
                SDCommand.APDU apdu = ECKeyAgreementEG.isdKeySetEstablishmentSendCert(smsrCert);
                addAPDU(apdu); // Record it.
                return super.sendTransaction(em, tr);
            case CREATE_ADDITIONAL_KEYSET:
                // The following according to Sec 5.6.1 of SGP 02 v3.1
                byte keyAccess = 0x00;
                byte[] sdin = null;
                try {
                    Eis eis = tr.eisEntry(em);
                    sdin = Utils.HEX.h2b(eis.findISDR().getSdin());
                } catch (Exception ex) {
                }
                byte[] initialCounter = Utils.encodeInteger(sequenceNumber, 5);
                byte[] a6 = ECKeyAgreementEG.makeA6CRT(3, sdin, hostID, Key.KIC_KEY_IDENTIFIER, keyVersionNumber,
                        initialCounter, keyAccess, KeyComponent.Type.AES,16, scenarioParam);
                addAPDU(ECKeyAgreementEG.isdKeySetEstablishmentSendKeyParams(ePk, a6, signature));
                return super.sendTransaction(em, tr);
        }
        return null;
    }

    @Override
    public boolean hasMore() {
        switch (stage) {
            default:
                return false;
            case HANDOVER_EUICC:
                return true;
            case AUTHENTICATE_SMSR:
            case CREATE_ADDITIONAL_KEYSET:
                return super.hasMore();
        }
    }

    public enum Stage {
        HANDOVER_EUICC, AUTHENTICATE_SMSR, CREATE_ADDITIONAL_KEYSET, HANDOVER_SUCCESS, COMPLETE, ERROR;
        private static Stage[] vals = values();

        public Stage next() {
            if (this == COMPLETE || this == ERROR)
                return this;
            return vals[(ordinal() + 1) % vals.length];
        }
    }
}
