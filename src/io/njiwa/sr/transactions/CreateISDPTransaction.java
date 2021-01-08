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
import io.njiwa.common.model.RpaEntity;
import io.njiwa.common.model.TransactionType;
import io.njiwa.common.ws.WSUtils;
import io.njiwa.common.ws.types.BaseResponseType;
import io.njiwa.common.ws.types.WsaEndPointReference;
import io.njiwa.common.SDCommand;
import io.njiwa.dp.ws.CommonImpl;
import io.njiwa.sr.model.AuditTrail;
import io.njiwa.sr.model.ProfileInfo;
import io.njiwa.sr.model.Eis;
import io.njiwa.sr.ota.Ota;
import io.njiwa.sr.ws.interfaces.ES3;

import javax.ejb.Asynchronous;
import javax.persistence.EntityManager;
import javax.persistence.LockModeType;
import javax.xml.ws.Holder;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;

/**
 * Created by bagyenda on 09/05/2017.
 */
public class CreateISDPTransaction extends SmSrBaseTransaction {

    public long profileID = -1;
    public long eidId = -1;

    public CreateISDPTransaction() {
    }

    public CreateISDPTransaction(final Eis eis, final ProfileInfo p) {
        this.eidId = eis.getId();
        this.profileID = p.getId();

        // Now make the CAPDU
        // First make the data
        ByteArrayOutputStream data = new ByteArrayOutputStream() {
            {
                try {
                    // According to Sec 4.1.1.1 of SGP 03 v3.0
                    byte[] x = Utils.HEX.h2b(eis.ISDPLOADFILEAID());
                    write(x.length & 0xFF);
                    write(x);

                    x = Utils.HEX.h2b(eis.ISDPMODULEAID());
                    write(x.length & 0xFF);
                    write(x);

                    x = Utils.HEX.h2b(p.getIsd_p_aid());
                    write(x.length & 0xFF);
                    write(x);
                    write(3); // Length of privileges
                    int priv1 = 0x80; // Is a security domain as per GPCS sec 11.1.2
                    int priv2 = 0x80 | 0x40; // Trusted path and authorised management
                    write(priv1 & 0xFF);
                    write(priv2 & 0xFF);
                    write(0);
                    // Make install parameters, table 10, Sec 4.1.1 of SGP.02 v4.2
                    ByteArrayOutputStream iparams = new ByteArrayOutputStream();
                    Utils.BER.appendTLV(iparams, (short) 0xC9, new byte[]{
                            (byte) 0x81, 0x02,
                            (byte) 0x03, 0x70 // SCP 03, "i" = 70 (See sec 5.1 of GPC Ammend. D, and Sec 2.5 of SGP.02 v4.2
                    });
                    int mem = p.getAllocatedMemory();
                    if (mem > 0) {
                        ByteArrayOutputStream memalloced = new ByteArrayOutputStream();
                        memalloced.write(new byte[]{(byte) 0x83, 2}); // Assume we can fit size into two bytes
                        Utils.appendEncodedInteger(memalloced, mem, 2);
                        Utils.BER.appendTLV(iparams, (short) 0xEF, memalloced.toByteArray());
                    }

                    write(iparams.size() & 0xFF);
                    write(iparams.toByteArray()); // Add them

                    write(0x00); // Size of install token = 0
                } catch (Exception ex) {
                }
            }
        };
        try {
            SDCommand.APDU apdu = new SDCommand.APDU(0x80, 0xe6, 0x0C, 0x00, data.toByteArray(), (short) 0);
            this.cAPDUs = new ArrayList<>();
            this.cAPDUs.add(apdu.toByteArray());
        } catch (Exception ex) {
        }
    }

    @Asynchronous
    @Override
    public synchronized void processResponse(EntityManager em, long tid, ResponseType rtype, String reqId) {
        String ispaid = null;
        String iccid = null;
        Ota.ResponseHandler.ETSI102226APDUResponses r = getResponses();
        byte[] resp = r.respData;
        try {
            ProfileInfo p = em.find(ProfileInfo.class, profileID, LockModeType.PESSIMISTIC_WRITE);
            if (p == null)
                throw new Exception(String.format("No such profile in CreateISPD response for eis[%d], profile ID" +
                        " [%d] "));
            if (rtype == ResponseType.SUCCESS) {
                p.setState(ProfileInfo.State.Created);
                ispaid = p.getIsd_p_aid();
                iccid = p.getIccid();
            } else {
                em.remove(p); // Remove it from the DB
            }
            em.flush();
        } catch (Exception ex) {
            Utils.lg.severe(String.format("Failed to process response to CreatedISP [eid:%d, profile:%d]: %s",
                    eidId,
                    profileID, ex));
        }


        if (status == null) {
            status = new BaseResponseType.ExecutionStatus(rtype == ResponseType.SUCCESS ? BaseResponseType.ExecutionStatus.Status
                    .ExecutedSuccess : BaseResponseType.ExecutionStatus.Status.Failed,
                    new BaseResponseType.ExecutionStatus.StatusCode("8.4", "CreateISDP", "4.2", ""));
        } else
            status.status = BaseResponseType.ExecutionStatus.Status.Failed;
        AuditTrail.addAuditTrail(em,tid, AuditTrail.OperationType.CreateISDP,status,ispaid,iccid,null,null);
        Date endDate = Calendar.getInstance().getTime(); // Set it

        final WsaEndPointReference sender = new WsaEndPointReference();
        sender.address = originallyTo;
        final Holder<String> msgType = new Holder<String>("http://gsma" +
                ".com/ES3/ProfileManagementCallBack/ES3-CreateISDP");

        try {
            if (requestingEntityId == RpaEntity.LOCAL_ENTITY_ID)
                CommonImpl.createISDPResponseHandler(em,ispaid,relatesTO, rtype == ResponseType.SUCCESS, resp != null ? Utils.HEX.b2H(resp) : null);
            else {
                final ES3 proxy = WSUtils.getPort("http://namespaces.gsma.org/esim-messaging/1", "ES3Port", getReplyToAddress(em, "ES3"), ES3.class, RpaEntity.Type.SMSR, em, requestingEntityId);
                proxy.createISDPResponse(sender, getReplyToAddress(em, "ES3").address, relatesTO, msgType, Utils.gregorianCalendarFromDate(startDate), Utils.gregorianCalendarFromDate(endDate), TransactionType.DEFAULT_VALIDITY_PERIOD, status, ispaid, resp != null ? Utils.HEX.b2H(resp) : null);
            }
        } catch (WSUtils.SuppressClientWSRequest wsa) {
        } catch (Exception ex) {
            Utils.lg.severe("Failed to issue async createisdp.response call: " + ex.getMessage());
        }
    }


}
