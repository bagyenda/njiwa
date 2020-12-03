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
import io.njiwa.common.SDCommand;
import io.njiwa.common.ws.types.BaseResponseType;
import io.njiwa.sr.model.AuditTrail;
import io.njiwa.sr.model.Eis;
import io.njiwa.sr.model.ProfileInfo;
import io.njiwa.sr.model.SmSrTransaction;
import io.njiwa.sr.ota.Ota;
import io.njiwa.sr.ws.CommonImpl;

import javax.persistence.EntityManager;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

/**
 * Created by bagyenda on 25/05/2017.
 */
public class AuditEISTransaction extends SmSrBaseTransaction {
    public long requestor;
    List<String> iccids;

    public AuditEISTransaction() {
    }


    public AuditEISTransaction(RpaEntity requestor, List<String> iccids, Eis eis) {
        this.requestor = requestor.getId();
        this.iccids = iccids;
        ProfileInfo p;
        // Sec 4.1.1.5 of SGP 02 v4.1
        addAPDU(new SDCommand.APDU(0x80, 0xCA, 0xFF, 0x21, null, (short)0)); // Get main card info.
        // Then get the apps
        List<ProfileInfo> l = eis.getProfiles();
        List<ProfileInfo> targetList;
        if (iccids == null)
            targetList = new ArrayList<>(l);
        else {
            targetList = new ArrayList<>();
            for (String s : iccids)
                if ((p = eis.findProfileByICCID(s)) != null)
                    targetList.add(p);
        }

        // Now make commands
        for (ProfileInfo profileInfo : targetList) {
            String aid = profileInfo.getIsd_p_aid();
            byte[] data = new ByteArrayOutputStream() {
                {
                    try {
                        Utils.BER.appendTLV(this, (short) 0x4F, Utils.HEX.h2b(aid));
                    } catch (Exception ex) {
                    }
                }
            }.toByteArray();
            addAPDU(new SDCommand.APDU(0x80, 0xF2, 0x40, 0x02, data)); // Sec 4.1.1.5 of SGP
        }

    }

    @Override
    public synchronized void processResponse(EntityManager em, long tid, TransactionType.ResponseType rtype, String reqId, byte[]
            response) {
        SmSrTransaction t = em.find(SmSrTransaction.class, tid);
        Eis eis = t.eisEntry(em);
        boolean gotResult;

        // Get first rapdu;
        Ota.ResponseHandler.ETSI102226APDUResponses r = getResponses();
        byte[] xdata = new byte[0];
        int sw1 = 0;
        if (r != null) {
            for (Ota.ResponseHandler.ETSI102226APDUResponses.Response response1 : r.responses)
                if (response1.type == Ota.ResponseHandler.ETSI102226APDUResponses.Response.ResponseType.RAPDU) {
                    xdata  = response1.data;
                    sw1 = response1.sw1;
                    break;
                }
        }
        try {
            if (!SDCommand.APDU.isSuccessCode(sw1))
                throw new Exception(String.format("Error: %s", Utils.HEX.b2H(response)));
            gotResult = true;
        } catch (Exception ex) {
            gotResult = false;
        }
        int numApplications = 0;
        long freeNonvolatileMem = 0;
        long freeVolatileMem = 0;
        ByteArrayInputStream xin = new ByteArrayInputStream(xdata);
        // Must contain a DGI with code FF 21
        try {
            Utils.Pair<Integer, byte[]> xres = Utils.DGI.decode(xin);
            if (xres.k != 0xFF21)
                Utils.lg.warning(String.format("Invalid DGI tag in AuditEIS response, got [0x%x]", xres.k));
            xin = new ByteArrayInputStream(xres.l);
        } catch (Exception ex) {

        }
        while (xin.available() > 0)
            try {

                Utils.Pair<InputStream, Integer> xres = Utils.BER.decodeTLV(xin);
                byte[] resp = Utils.getBytes(xres.k);
                int tag = xres.l & 0xFF;
                // Look at the data,  Sec 8.2.1.7.2 of ETSI TS 102 226
                switch (tag) {
                    case 0x81:
                        numApplications = resp[0];
                        break;
                    case 0x82:
                        freeNonvolatileMem = Utils.BER.decodeInt(resp,resp.length);
                        break;
                    case 0x83:
                        freeVolatileMem = Utils.BER.decodeInt(resp,resp.length);
                    default:
                        break;
                }
            } catch (Exception ex) {
                Utils.lg.severe(String.format("Failed to process response to auditeis [tr:%s]: %s",
                        t,
                        ex));
            }

        Utils.lg.info(String.format("auditeis [tr:%s, success: %s]: apps: %d, free non volatile ram: %d, free volatile ram: %d",
                t, gotResult,
                numApplications,freeNonvolatileMem,freeVolatileMem));
        if (!hasMore()) {
            RpaEntity requestor = em.find(RpaEntity.class, this.requestor);
            if (status == null)
                status = new BaseResponseType.ExecutionStatus(
                        rtype == TransactionType.ResponseType.SUCCESS ? BaseResponseType.ExecutionStatus.Status.ExecutedSuccess :
                                BaseResponseType.ExecutionStatus.Status.Failed,
                        new BaseResponseType.ExecutionStatus.StatusCode("8.4", "", "4.2", ""));
            // Log to audit
            eis.addToAuditTrail(em,
                    new AuditTrail(eis, startDate, AuditTrail.OperationType.eUICCCapabilityAudit,
                            requestor, status, null, null, null, null));
            // Send to the requestor, since we got all our information
            CommonImpl.sendAuditEISResponse(em, this, eis, iccids, requestor);
        }
    }

}
