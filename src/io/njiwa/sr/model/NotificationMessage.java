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

package io.njiwa.sr.model;

import io.njiwa.common.model.RpaEntity;
import io.njiwa.common.model.TransactionType;
import io.njiwa.common.SDCommand;
import io.njiwa.common.Utils;
import io.njiwa.sr.transactions.SmSrBaseTransaction;

import javax.persistence.EntityManager;
import javax.persistence.LockModeType;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by bagyenda on 09/11/2016.
 */
public class NotificationMessage {
    public Eis eis; // The parsed Eis
    public Type notificationType;
    public int sequenceNumber;
    public String isdPAid;
    public ProfileInfo profile; // Might be NULL
    public String imei;
    public String meid;
    public String eid;

    public static NotificationMessage parseNotification(EntityManager em, InputStream in) throws Exception {
        NotificationMessage msg = new NotificationMessage();

        Utils.Pair<InputStream, Integer> xres = Utils.BER.decodeTLV(in);
        if (xres.l != 0xE1)
            throw new Exception(String.format("Invalid notification message tag [%02x]", xres.l));
        // Rest is as per sec 4.1.1.11 of SGP doc; simply loop
        InputStream xInput = xres.k;
        Utils.Pair<InputStream, Integer> res;
        byte[] xdata;
        int notificationType = -1;
        while (xInput.available() > 0 &&
                (res = Utils.BER.decodeTLV(xInput)) != null) {
            xdata = Utils.getBytes(res.k);

            switch (res.l) {
                case 0x4C: // Eid
                    msg.eid = Utils.HEX.b2h(xdata);
                    msg.eis = Eis.findByEid(em, xdata);
                    break;
                case 0x4D:
                    notificationType = xdata[0];
                    msg.notificationType = NotificationMessage.Type.fromInt(notificationType);
                    break;
                case 0x2F:
                case 0xAf: // ETSI TS 101 220

                    msg.isdPAid = Utils.HEX.b2h(xdata);
                    break;
                case 0x14:
                case 0x94:
                    msg.imei = Utils.HEX.b2H(xdata);
                    break;
                case 0x6D:
                case 0xED:
                    msg.meid = Utils.HEX.b2H(xdata);
                    break;
                case 0x4E:
                    msg.sequenceNumber = (int) Utils.BER.decodeInt(xdata, 2);
                    break;
                default:
                    throw new Exception(String.format("Invalid tag in notification message tag [%02x]!", res
                            .l));
            }

        }

        try {
            // Try to look for the profile, ignore failure. Right? e.g. if it is merely a network latch-on notification
            msg.profile = msg.eis.findProfileByAID(msg.isdPAid);
            // Log it to audit trail
            RpaEntity us = RpaEntity.getLocal(RpaEntity.Type.SMSR);
            String ourOID = us != null ? us.getOid() : null;
            AuditTrail a = new AuditTrail(msg.eis, notificationType, null, msg.isdPAid, msg.profile != null ? msg.profile.getIccid()
                    : null, msg.imei, msg.meid, ourOID);
            msg.eis.addToAuditTrail(em, a);
        } catch (Exception ex) {
        }
        return msg;
    }

    public String toString() {

        String res = "";
        try {
            res = (eis != null) ? String.format("From: %s") : String.format("From: %s", eid);
            res += ", Type: " + notificationType;
            res += ", Seq: " + sequenceNumber;
            if (isdPAid != null)
                res += ", AID: " + isdPAid;
            if (imei != null)
                res += ", IMEI: " + imei;
            if (meid != null)
                res += ", MEID: " + meid;
        } catch (Exception ex) {

        }
        return res;
    }

    public enum Type {
        eUICCDeclaration, ProfileChangeSucceeded, ProfileChangeFailedAndRollback, Void,
        ProfileChangeAfterFallBack, RFU;

        public static Type fromInt(int code) {
            switch (code) {
                case 0x01:
                    return eUICCDeclaration;
                case 0x02:
                    return ProfileChangeSucceeded;
                case 0x03:
                    return ProfileChangeFailedAndRollback;
                case 0x04:
                    return Void;
                case 0x05:
                    return ProfileChangeAfterFallBack;
                default:
                    return RFU;
            }
        }
    }

    /**
     * @brief This represents a notification confirmation transaction, including how to handle its response
     */
    public static class HandleNotificationConfirmationTransaction extends SmSrBaseTransaction {

        public Long relatesTo; // Related transaction

        public HandleNotificationConfirmationTransaction() {
        }

        public HandleNotificationConfirmationTransaction(Long relatesTo, final int
                seqNum, Long requestingEntity) {
            this.relatesTo = relatesTo;
            this.requestingEntityId = requestingEntity;
            ByteArrayOutputStream data = new ByteArrayOutputStream() {
                {
                    try {
                        byte[] seqOs = new ByteArrayOutputStream() {{
                            byte[] s = Utils.encodeInteger(seqNum, 2);
                            Utils.BER.appendTLV(this,0x4E,s);
                        }}.toByteArray();


                        Utils.BER.appendTLV(this,
                                new byte[]{0x3A, 0x08}, // Sec 4.1.1.12 of SGP doc
                            seqOs);
                    } catch (Exception e) {
                    }
                }
            };
            try {
                this.cAPDUs = new ArrayList<byte[]>();
                this.cAPDUs.add(new SDCommand.APDU(0x80, 0xE2, 0x89, 0x00, data.toByteArray()).toByteArray());
            } catch (Exception ex) {
            }
        }

        /**
         * @param in
         * @return
         * @throws Exception
         * @brief examine a notification confirmation in accordance with Sec 4.1.1.12 of SGP v3.0
         */
        private List<String> parseNotificationConfirmation(InputStream in) throws Exception {
            List<String> l = new ArrayList<String>();
            Utils.Pair<InputStream, Integer> xres = Utils.BER.decodeTLV(in);
            if (xres.l != 0x80)
                throw new Exception(String.format("Invalid tag [%02x], expected 0x80", xres.l));
            InputStream xInput = xres.k;
            Utils.Pair<InputStream, Integer> res;

            while (xInput.available() > 0 &&
                    (res = Utils.BER.decodeTLV(xInput)) != null)
                if (res.l != 0x4F)
                    throw new Exception(String.format("Invalid tag [%02x], expected 0x4F", xres.l));
                else {
                    byte[] xdata = Utils.getBytes(res.k);
                    l.add(Utils.HEX.b2H(xdata));
                }
            return l;
        }

        @Override
        /**
         * @brief
         * When a notification confirmation is received, we need to relate it to the original transaction that was
         * the reason the device sent a notification in the first place. that transaction must have been of the
         * Profile Change kind (or a network attach notification, in which case we don't care about the response
         * anyway..
         */
        public synchronized void processResponse(EntityManager em, long tid, TransactionType.ResponseType rtype, String reqId, byte[]
                response) {
            if (relatesTo == null)
                return;
            try {
                // Look for the transaction and its object, which must be of type HandleNotification
                SmSrTransaction t = em.find(SmSrTransaction.class, relatesTo, LockModeType.PESSIMISTIC_WRITE); // Might
                // be NULL
                ProfileInfo.HandleNotification pHandler = (ProfileInfo.HandleNotification) t.getTransObject();
                List<String> aids = rtype == ResponseType.SUCCESS ? parseNotificationConfirmation(new
                        ByteArrayInputStream(response)) : null;
                pHandler.processNotificationConfirmation(em, rtype, aids); // This does whatever updates are required.
                Eis eis = t.eisEntry(em);
                ProfileInfo.clearProfileChangFlag(em, relatesTo, eis);
                Utils.lg.info(String.format("Processed notification confirmation for " +
                        "notification transaction [%s]", tid));
            } catch (Exception ex) {
                Utils.lg.severe(String.format("Error processing notification confirmation for " +
                        "notification transaction [%s]: %s", tid, ex));
            }
        }
    }


}
