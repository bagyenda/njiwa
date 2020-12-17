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
import io.njiwa.common.model.TransactionType;
import io.njiwa.common.ws.types.BaseResponseType;
import io.njiwa.common.SDCommand;
import io.njiwa.sr.ws.CommonImpl;
import io.njiwa.sr.model.*;

import javax.persistence.EntityManager;
import javax.persistence.LockModeType;
import java.io.ByteArrayOutputStream;
import java.util.List;

/**
 * Created by bagyenda on 09/05/2017.
 */
public class DisableProfileTransaction extends SmSrBaseTransaction implements ProfileInfo.HandleNotification {
    public long profileID = -1;
    public long eidId = -1;
    public boolean deleteAfter = false;

    public boolean responseReceived = false;
    public NotificationMessage.Type notificationType;
    public byte[] response;
    public Long ourTransactionId = null;

    public DisableProfileTransaction() {
    }

    public DisableProfileTransaction(final ProfileInfo p, boolean deleteAfter) {
        this.profileID = p.getId();
        Eis eis = p.getEis();
        this.eidId = eis.getId();
        this.deleteAfter = deleteAfter; // Whether to delete it after disabling it.
        int ins = 0xe2, p1 = 0x88, p2 = 0;
        ByteArrayOutputStream data = new ByteArrayOutputStream() {
            {
                // According to Sec 4.1.1.2 of SGP 03 v4.2, Table 13
                String aid = p.getIsd_p_aid();
                ByteArrayOutputStream os = new ByteArrayOutputStream();
                try {
                    Utils.BER.appendTLV(os, (short) 0x4F, Utils.HEX.h2b(aid));
                     Utils.BER.appendTLV (this, new byte[]{(byte) 0x3A, (byte) 0x04},
                             os.toByteArray());
                } catch (Exception ex) {
                }

            }
        };
        addAPDU(new SDCommand.APDU(0x80, ins, p1, p2, data.toByteArray(), null));

    }

    @Override
    public synchronized void processResponse(EntityManager em, long tid, TransactionType.ResponseType rtype, String reqId, byte[]
            response) {
        String iccid = null;
        String aid = null;
        try {
            responseReceived = true;
            this.response = response;
            ourTransactionId = tid;
            ProfileInfo p = em.find(ProfileInfo.class, profileID, LockModeType.PESSIMISTIC_WRITE);
            if (p == null)
                throw new Exception(String.format("No such profile in disable ISP-D Status response for eis[%d], " +
                        "profile ID" +
                        " [%d] "));
            iccid = p.getIccid();
            aid = p.getIsd_p_aid();
            if (status == null)
               status =  new BaseResponseType.ExecutionStatus(
                       rtype == TransactionType.ResponseType.SUCCESS ? BaseResponseType.ExecutionStatus.Status.ExecutedSuccess :
                       BaseResponseType.ExecutionStatus.Status.Failed,
                        new BaseResponseType.ExecutionStatus.StatusCode("8.4", "", "4.2", ""));
            AuditTrail.addAuditTrail(em, tid, AuditTrail.OperationType.DisableProfile, status, aid, iccid, null, null);
        } catch (Exception ex) {
            Utils.lg.severe(String.format("Failed to process response to disableProfile [eid:%d, profile:%d]: %s",
                    eidId,
                    profileID, ex));
        }

        if (rtype != TransactionType.ResponseType.SUCCESS) {
            if (deleteAfter)
                CommonImpl.sendDeleteProfileResponse(em, this, response);
            else
                CommonImpl.sendDisableProfileResponse(em, this, response);
        }
        // Otherwise, wait for the notifications...
    }

    @Override
    public void processNotification(NotificationMessage msg, EntityManager em) throws Exception {
        try {
            this.notificationType = msg.notificationType; // Remember it for when we receive the confirmation


            // We must have received a ChangeFailedAndRollback or ChangeAfterFallBack
            switch (msg.notificationType) {
                case ProfileChangeAfterFallBack:
                    if (msg.profile == null)
                        throw new Exception("No such profile on eUICC!");
                    ProfileInfo pLast = msg.eis.findEnabledProfile();
                    if (pLast != null && pLast != msg.profile)
                        pLast.setState(ProfileInfo.State.Disabled); // Disable it.

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
            Utils.lg.severe(String.format("Failed to process notification [%s] to disableProfile : %s",
                    msg,
                    ex));
            throw ex; // Toss it.
        }

        // Upper level (Eis) will create a transaction to send the notification confirmation to euicc
        // XXX We do however need to notify  the losing and active MNO via ES2
    }

    @Override
    public void processNotificationConfirmation(EntityManager em, TransactionType.ResponseType rtype, List<String> aids) {
        // When we receive the confirmation, we must:
        // - If deleteAfter flag not set, then do a callback to the caller.
        // - if we had a deleteAfter and we were successful, make a Delete transaction, but only if it wasn't
        // already deleted on the euICC


        if (!deleteAfter) {
            status = new BaseResponseType.ExecutionStatus(notificationType == NotificationMessage.Type
                    .ProfileChangeAfterFallBack ? BaseResponseType.ExecutionStatus.Status.ExecutedSuccess :
                    BaseResponseType.ExecutionStatus
                            .Status
                            .Failed,
                    new BaseResponseType.ExecutionStatus.StatusCode("8.4", "", "4.2", ""));
            // XXX from might not be set. Right??
            CommonImpl.sendDisableProfileResponse(em, this, response);
        }

        ProfileInfo pPrev = em.find(ProfileInfo.class, profileID);
        Pol2Rule.Qualification q = pPrev != null ? Pol2Rule.qualificationAction(pPrev.getPol2(), Pol2Rule.Action
                .DISABLE) : Pol2Rule.Qualification.NotAllowed;
        Eis eis = Eis.deleteProfiles(em, eidId, aids);
        ProfileInfo.State curState = pPrev != null ? pPrev.getState() : ProfileInfo.State.Deleted;
        // At this point if the profile has been disabled *but* has not deleted *yet* it's Pol2 says
        // it should have been, then send a command to delete it.
        // OR if deleteAfter was set, then do the same thing
        if (deleteAfter ||
                (notificationType == NotificationMessage.Type.ProfileChangeAfterFallBack
                        && curState != ProfileInfo.State.Deleted && q != null && q == Pol2Rule.Qualification.AutoDelete))
            try {

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
