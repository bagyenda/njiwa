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
import io.njiwa.common.SDCommand;
import io.njiwa.common.ws.types.BaseResponseType;
import io.njiwa.sr.model.AuditTrail;
import io.njiwa.sr.model.Eis;
import io.njiwa.sr.model.NotificationMessage;
import io.njiwa.sr.model.ProfileInfo;
import io.njiwa.sr.ota.Ota;
import io.njiwa.sr.ws.CommonImpl;

import javax.persistence.EntityManager;
import javax.persistence.LockModeType;
import java.io.ByteArrayOutputStream;
import java.util.List;

/**
 * Created by bagyenda on 09/05/2017.
 */
public class DeleteProfileTransaction extends SmSrBaseTransaction implements ProfileInfo.HandleNotification {
    public long profileID = -1;
    public long eidId = -1;

    public DeleteProfileTransaction() {
    }

    public DeleteProfileTransaction(final ProfileInfo p) {
        this.profileID = p.getId();
        Eis eis = p.getEis();
        this.eidId = eis.getId();
        int ins = 0xe2, p1 = 0x88, p2 = 0;
        ByteArrayOutputStream data;

        p2 = 0x40;
        ins = 0xE4;
        p1 = 0;
        data = new ByteArrayOutputStream() {
            {
                // According to Sec 4.1.1.2 of SGP 03 v3.0
                String aid = p.getIsd_p_aid();

                try {
                    Utils.BER.appendTLV(this, (short) 0x4F, Utils.HEX.h2b(aid));
                } catch (Exception ex) {
                }

            }
        };
        addAPDU(new SDCommand.APDU(0x80, ins, p1, p2, data.toByteArray(), null));
    }

    @Override
    public synchronized void processResponse(EntityManager em, long tid, ResponseType rtype, String reqId) {
        // Process response, report to the caller.
        try {
            ProfileInfo p = em.find(ProfileInfo.class, profileID, LockModeType.PESSIMISTIC_WRITE);
            if (p == null)
                throw new Exception(String.format("No such profile in delete ISP-D Status response for eis[%d], " +
                        "profile ID" +
                        " [%d] "));

            p.setState(ProfileInfo.State.Deleted);
            // Clear the profile change flag: Because this one may not require a notification
            ProfileInfo.clearProfileChangFlag(em, tid, p.getEis());
            String iccid = p.getIccid();
            String aid = p.getIsd_p_aid();
            em.remove(p); // Remove from the chain
            if (rtype == ResponseType.SUCCESS)
                status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status
                        .ExecutedSuccess, new BaseResponseType.ExecutionStatus.StatusCode("8.4", "", "4.2", ""));
            // XXX if it was created internally, then there is no from and to

            Ota.ResponseHandler.ETSI102226APDUResponses r = getResponses();

            AuditTrail.addAuditTrail(em, tid, AuditTrail.OperationType.DeleteProfile, status, aid, iccid, null, null);
            CommonImpl.sendDeleteProfileResponse(em,this,r.respData);
        } catch (Exception ex) {
            Utils.lg.severe(String.format("Failed to process response to deleteISDP [eid:%d, profile:%d]: %s",
                    eidId,
                    profileID, ex));
        }

    }

    @Override
    public void processNotification(NotificationMessage msg, EntityManager em) throws Exception {
        // Nothing to do, really, except enable whatever is enabled

        if (msg.profile == null)
            throw new Exception("No such profile on eUICC!");
        msg.profile.setState(ProfileInfo.State.Enabled); // Make it enabled

    }

    @Override
    public void processNotificationConfirmation(EntityManager em, ResponseType rtype, List<String> aids) {
        // Nothing to do, response handler has already reported
    }
}
