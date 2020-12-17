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

import io.njiwa.common.SDCommand;
import io.njiwa.common.Utils;
import io.njiwa.common.ws.types.BaseResponseType;
import io.njiwa.sr.model.*;
import io.njiwa.sr.ws.CommonImpl;

import javax.persistence.EntityManager;
import javax.persistence.LockModeType;
import java.io.ByteArrayOutputStream;
import java.util.List;

/**
 * Created by bagyenda on 09/05/2017.
 */
public class EnableProfileTransaction extends SmSrBaseTransaction implements ProfileInfo.HandleNotification {
    public long profileID = -1;
    public Long previousProfileID = null;
    public long eidId = -1;
    public boolean responseReceived = false;
    public NotificationMessage.Type notificationType;
    public byte[] response;
    public Long ourTransactionId = null;

    public EnableProfileTransaction() {
    }

    public EnableProfileTransaction(final ProfileInfo p) {
        this.profileID = p.getId();
        Eis eis = p.getEis();
        this.eidId = eis.getId();

        // eis.setPendingProfileChangeTransaction(tid);
        int ins = 0xe2, p1 = 0x88, p2 = 0;
        ByteArrayOutputStream data;

        data = new ByteArrayOutputStream() {
            {
                // According to Sec 4.1.1.2 of SGP 03 v3.0
                String aid = p.getIsd_p_aid();
                ByteArrayOutputStream os = new ByteArrayOutputStream();
                try {
                    Utils.BER.appendTLV(os, (short) 0x4F, Utils.HEX.h2b(aid));
                   Utils.BER.appendTLV(this, new byte[]{(byte) 0x3A, (byte) 0x03}, os.toByteArray());
                } catch (Exception ex) {
                }

            }
        };

        addAPDU(new SDCommand.APDU(0x80, ins, p1, p2, data.toByteArray(), null));
    }

    @Override
    public synchronized void processResponse(EntityManager em, long tid, ResponseType rtype, String reqId, byte[]
            response) {
        try {
            responseReceived = true;
            this.response = response;
            ourTransactionId = tid;
            ProfileInfo p = em.find(ProfileInfo.class, profileID, LockModeType.PESSIMISTIC_WRITE);
            if (p == null)
                throw new Exception(String.format("No such profile in enable ISD-P Status response for eis[%d], " +
                        "profile ID" +
                        " [%d] "));
            String iccid = p.getIccid();
            String aid = p.getIsd_p_aid();
            if (status == null)
                status =  new BaseResponseType.ExecutionStatus(
                        rtype == ResponseType.SUCCESS ? BaseResponseType.ExecutionStatus.Status.ExecutedSuccess :
                                BaseResponseType.ExecutionStatus.Status.Failed,
                        new BaseResponseType.ExecutionStatus.StatusCode("8.4", "", "4.2", ""));
            AuditTrail.addAuditTrail(em, tid, AuditTrail.OperationType.EnableProfile, status, aid, iccid, null, null);
        } catch (Exception ex) {
            Utils.lg.severe(String.format("Failed to process response to enableProfile [eid:%d, profile:%d]: %s",
                    eidId,
                    profileID, ex));
        }

        if (rtype != ResponseType.SUCCESS)
            CommonImpl.sendEnableProfileResponse(em,this,response);
    }

    @Override
    public void processNotification(NotificationMessage msg, EntityManager em) throws Exception {
        // must be either type ChangeSucceeded or ChangeFailedAndRollBack
        try {
            this.notificationType = msg.notificationType; // Remember it for when we receive the confirmation
            ProfileInfo pEnabled = msg.eis.findEnabledProfile();
            previousProfileID = pEnabled != null ? pEnabled.getId() : null; // Grab the enabled Profile
            switch (msg.notificationType) {
                case ProfileChangeSucceeded:
                    ProfileInfo pLast = msg.eis.findEnabledProfile();
                    if (pLast != null && pLast != msg.profile)
                        pLast.setState(ProfileInfo.State.Disabled); // Disable it.
                    if (msg.profile == null)
                        throw new Exception("No such profile on eUICC!");
                    msg.profile.setState(ProfileInfo.State.Enabled);
                    // msg.eis.setPendingProfileChangeTransaction(null); // We are done.
                    break;
                case ProfileChangeFailedAndRollback:
                    if (msg.profile == null)
                        throw new Exception("No such profile on eUICC!");
                    // Whatever what set to be enabled is not enabled now...
                    msg.profile.setState(ProfileInfo.State.Enabled);

                    // We wait for the notification confirmation transaction to end to clear the
                    // PendingProfileUpdateTransactionId flag on the eUICC record
                    break;
                default:
                    throw new Exception("Invalid notification type received");

            }
        } catch (Exception ex) {
            Utils.lg.severe(String.format("Failed to process notification [%s] to enableProfile : %s",
                    msg,
                    ex));
            throw ex; // Toss it.
        }

        // Upper level (Eis) will create a transaction to send the notification confirmation
    }

    private ProfileInfo getPreviousProfile(EntityManager em) {
        try {
            return em.find(ProfileInfo.class, previousProfileID, LockModeType.PESSIMISTIC_WRITE);
        } catch (Exception ex) {
        }
        return null;
    }

    @Override
    public void processNotificationConfirmation(EntityManager em, ResponseType rtype, List<String> aids) {
        // Regardless of the result of the notification confirmation, inform the requestor
        status = new BaseResponseType.ExecutionStatus(notificationType == NotificationMessage.Type
                .ProfileChangeSucceeded ? BaseResponseType.ExecutionStatus.Status.ExecutedSuccess :
                BaseResponseType.ExecutionStatus
                        .Status
                        .Failed,
                new BaseResponseType.ExecutionStatus.StatusCode("8.4", "", "4.2", ""));
        // XXX from might not be set. Right??
        CommonImpl.sendEnableProfileResponse(em,this,response);
        // Then process the received message:
        Eis eis = Eis.deleteProfiles(em, eidId, aids);
        // At this point if the new profile has been enabled *but* old one was not deleted *yet* it's Pol2 says
        // it should have been, then send a command to delete it.
        if (notificationType == NotificationMessage.Type.ProfileChangeSucceeded)
            try {
                ProfileInfo pPrev = getPreviousProfile(em);
                Pol2Rule.Qualification q = Pol2Rule.qualificationAction(pPrev.getPol2(), Pol2Rule.Action.DISABLE);
                // We get here if the previous profile still exists.
                if (pPrev.getState() != ProfileInfo.State.Deleted && q == Pol2Rule.Qualification.AutoDelete) {
                    // Send a deleteISP command, specifying that it targets this profile
                    DeleteProfileTransaction dP = new DeleteProfileTransaction(pPrev);
                    SmSrTransaction t = new SmSrTransaction("deleteISDP", "", null, eidId, validity, false, dP);
                    t.setRelatesToTransaction(ourTransactionId); // Mark it as related to this last one
                    em.persist(t); // Send to DB
                    eis.setPendingProfileChangeTransaction(t.getId()); // Grab the blocking one.
                }
            } catch (Exception ex) {
            }
        em.flush();
    }
}
