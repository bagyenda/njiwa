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
        ByteArrayInputStream xin = new ByteArrayInputStream(response);
        while (xin.available() > 0)
            try {

                Utils.Pair<InputStream, Integer> xres = Utils.BER.decodeTLV(xin);
                // TAG must be R_APDU
                byte[] resp = Utils.getBytes(xres.k);
                // Get response code
                int sw1 = resp[resp.length - 2];
                if (!SDCommand.APDU.isSuccessCode(sw1))
                    throw new Exception(String.format("Error: %s", Utils.HEX.b2H(response)));
                // Parse the data
                InputStream in = new ByteArrayInputStream(resp);
                Utils.Pair<InputStream, Integer> xres2 = Utils.BER.decodeTLV(in);
                if (xres2.l != 0xE3)
                    throw new Exception(String.format("Unexpected result tag [%02x], expected E3", xres.k));
                // Look at the data, based on table 28 of SGP and Sec 8.2.1.7.2 of ETSI TS 102 226
                in = xres2.k;
                xres2 = Utils.BER.decodeTLV(in);
                // XX for now ignore card info
                if (xres2.l == 0x4F) {
                    byte[] aid = Utils.getBytes(xres2.k);
                    // Read LCS and Attr.
                    xres2 = Utils.BER.decodeTLV(in);
                    byte lcs = Utils.getBytes(xres2.k)[0];
                    xres2 = Utils.BER.decodeTLV(in);
                    byte attr = Utils.getBytes(xres2.k)[0];

                    // Find Profile, update it
                    ProfileInfo p = eis.findProfileByAID(Utils.HEX.b2H(aid));
                    p.setState(ProfileInfo.State.fromCode(lcs));
                    p.setFallbackAttr((attr & 0x01) != 0);
                    eis.setLastAuditDate(Calendar.getInstance().getTime());
                }
            } catch (Exception ex) {
                Utils.lg.severe(String.format("Failed to process response to auditeis [tr:%s]: %s",
                        t,
                        ex));
            }
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
