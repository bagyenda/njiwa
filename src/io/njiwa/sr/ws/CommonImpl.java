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

package io.njiwa.sr.ws;

import io.njiwa.common.SDCommand;
import io.njiwa.common.Utils;
import io.njiwa.common.model.RpaEntity;
import io.njiwa.common.model.TransactionType;
import io.njiwa.common.ws.WSUtils;
import io.njiwa.common.ws.handlers.Authenticator;
import io.njiwa.common.ws.types.BaseResponseType;
import io.njiwa.common.ws.types.BaseTransactionType;
import io.njiwa.common.ws.types.WsaEndPointReference;
import io.njiwa.dp.transactions.ChangeProfileStatusTransaction;
import io.njiwa.sr.model.Pol2Rule;
import io.njiwa.sr.model.ProfileInfo;
import io.njiwa.sr.model.SecurityDomain;
import io.njiwa.sr.model.SmSrTransaction;
import io.njiwa.sr.transactions.*;
import io.njiwa.sr.ws.interfaces.ES3;
import io.njiwa.sr.ws.interfaces.ES4;
import io.njiwa.sr.ws.types.Eis;
import io.njiwa.sr.ws.types.Pol2Type;
import io.njiwa.sr.ws.types.SubscriptionAddress;

import javax.persistence.EntityManager;
import javax.xml.ws.Holder;
import javax.xml.ws.WebServiceContext;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

/**
 * Created by bagyenda on 25/05/2017.
 */
public class CommonImpl {
    // Functions in common to ES3 and ES4


    public static BaseResponseType updatePolicyRules(EntityManager em, RpaEntity sender, String eid, String iccid,
                                                     Pol2Type pol2) {
        Date startDate = Calendar.getInstance().getTime();

        final BaseResponseType.ExecutionStatus.StatusCode code = new BaseResponseType.ExecutionStatus.StatusCode();
        code.subjectCode = "8.1.1";
        code.reasonCode = "";
        code.message = "";
        code.subjectIdentifier = "";

        ProfileInfo p = null;
        BaseResponseType.ExecutionStatus status =
                new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.ExecutedSuccess, code);

        // Find eis
        io.njiwa.sr.model.Eis eis = findAndCheckeUICC(em, eid, sender, status);
        if (eis != null && (p = eis.findProfileByICCID(iccid)) == null) {
            status.status = BaseResponseType.ExecutionStatus.Status.Failed;
            status.statusCodeData.subjectCode = "8.2.1";
            status.statusCodeData.reasonCode = "3.9";
            status.statusCodeData.subjectIdentifier = "Profile ICCID";
            status.statusCodeData.message = "Unknown profile for given EID";
        } else if (p != null && p.getState() != ProfileInfo.State.Enabled && p.getState() != ProfileInfo.State.Disabled) {
            status.status = BaseResponseType.ExecutionStatus.Status.Failed;
            status.statusCodeData.subjectCode = "8.2.1";
            status.statusCodeData.reasonCode = "1.2";
            status.statusCodeData.subjectIdentifier = "Profile ICCID";
            status.statusCodeData.message = "Wrong profile state!";
        } else if (p != null) {
            // Check ownership
            RpaEntity.Type senderType = sender.getType();
            String owner = senderType == RpaEntity.Type.SMDP ? p.getSmdpOID() : p.getMno_id();
            if (sender.getType() != senderType || owner == null || !sender.getOid().equals(owner)) {
                status.status = BaseResponseType.ExecutionStatus.Status.Failed;
                status.statusCodeData.subjectCode = "8.2.3";
                status.statusCodeData.reasonCode = "2.1";
                status.statusCodeData.subjectIdentifier = "Profile owner";
                status.statusCodeData.message = "Not owner!";
            } else if (pol2 != null) pol2.toModel(p);
        }

        Date endDate = Calendar.getInstance().getTime();

        BaseResponseType resp = new BaseResponseType(startDate, endDate, BaseTransactionType.DEFAULT_VALIDITY_PERIOD,
                status);
        return resp;
    }

    public static Long auditEIS(EntityManager em, RpaEntity sender, String eid, List<String> iccids,
                                BaseResponseType.ExecutionStatus status, RpaEntity.Type senderType,
                                WsaEndPointReference senderEntity, String receiverEntity, String messageId,
                                long validityPeriod, WsaEndPointReference replyTo, Holder<String> messageType) {

        // Find eis
        io.njiwa.sr.model.Eis eis = findAndCheckeUICC(em, eid, sender, status);
        AuditEISTransaction st = new AuditEISTransaction(sender, iccids, eis);
        st.updateBaseData(senderEntity, receiverEntity, messageId, validityPeriod, replyTo, sender.getId());
        st.requestorType = senderType;
        try {
            SmSrTransaction transaction = new SmSrTransaction(em, messageType.value, messageId, receiverEntity, eid,
                    validityPeriod, false, st);
            em.persist(transaction);
            return transaction.getId();
        } catch (Exception ex) {
            String xs = ex.getMessage();
            return null;
        }
    }

    private static io.njiwa.sr.model.Eis findAndCheckeUICC(EntityManager em, String eid, RpaEntity sender,
                                                           BaseResponseType.ExecutionStatus status) {
        io.njiwa.sr.model.Eis eis = io.njiwa.sr.model.Eis.findByEid(em, eid);
        if (eis == null) {
            status.status = BaseResponseType.ExecutionStatus.Status.Failed;
            status.statusCodeData.message = "EIS exists";
            status.statusCodeData.subjectCode = "8.1.1";
            status.statusCodeData.reasonCode = "1.1";
            return null;
        } else if (sender.getType() != RpaEntity.Type.MNO && sender.getType() != RpaEntity.Type.SMDP) {
            status.status = BaseResponseType.ExecutionStatus.Status.Failed;
            status.statusCodeData.message = "Not allowed";
            status.statusCodeData.subjectCode = "8.1";
            status.statusCodeData.reasonCode = "1.2";
            return null;
        } else if (!eis.managementAllowed(sender.getOid())) {
            status.status = BaseResponseType.ExecutionStatus.Status.Failed;
            status.statusCodeData.message = "Not allowed";
            status.statusCodeData.subjectCode = "8.1";
            status.statusCodeData.reasonCode = "1.2";
            return null;
        } else

            // Check for pending euicc handover
            if (eis.verifyPendingEuiCCHandoverTransaction(em)) {
                status.status = BaseResponseType.ExecutionStatus.Status.Failed;
                status.statusCodeData.subjectCode = "1.2";
                status.statusCodeData.reasonCode = "4.4";
                status.statusCodeData.message = "EIS busy: Handover in progress";
                return null;
            }

        return eis;
    }

    private static Utils.Pair<Boolean, ProfileInfo> validateOwnerAction(io.njiwa.sr.model.Eis eis, String iccid,
                                                                        RpaEntity sender,
                                                                        BaseResponseType.ExecutionStatus status) {

        try {
            ProfileInfo profileInfo = eis.findProfileByICCID(iccid);
            RpaEntity.Type senderType = sender.getType();
            // Check ownership
            String owner = senderType == RpaEntity.Type.SMDP ? profileInfo.getSmdpOID() : profileInfo.getMno_id();
            if (owner == null || sender.getType() != senderType || !owner.equalsIgnoreCase(sender.getOid())) {
                status.status = BaseResponseType.ExecutionStatus.Status.Failed;
                status.statusCodeData.subjectCode = "8.2.1";
                status.statusCodeData.subjectIdentifier = "1.2";
                status.statusCodeData.message = "Not permitted";
                return new Utils.Pair<>(false, null);
            }
            return new Utils.Pair<>(true, profileInfo);
        } catch (Exception ex) {
        }
        return new Utils.Pair<>(false, null);
    }

    public static Long deleteProfile(EntityManager em, RpaEntity sender, String eid,
                                     BaseResponseType.ExecutionStatus status, String iccid,
             WsaEndPointReference senderEntity, String receiverEntity, String messageId, long validityPeriod,
                                     WsaEndPointReference replyTo, Holder<String> messageType) {

        try {

            // Find eis
            io.njiwa.sr.model.Eis eis = findAndCheckeUICC(em, eid, sender, status);
            ProfileInfo profileInfo = null;
            // Now check for one with matching ICCID
            try {
                Utils.Pair<Boolean, ProfileInfo> p = validateOwnerAction(eis, iccid, sender, status);
                profileInfo = p.l;

                // Check ownership
                if (!p.k) return null;

                ProfileInfo.State state = profileInfo.getState();
                if (state == ProfileInfo.State.InstallInProgress || state == ProfileInfo.State.Created) {
                    status.status = BaseResponseType.ExecutionStatus.Status.Failed;
                    status.statusCodeData.subjectCode = "8.2.1";
                    status.statusCodeData.subjectIdentifier = "1.2";
                    status.statusCodeData.message = "Profile state is wrong";
                    return null;
                }
            } catch (Exception ex) {
                status.status = BaseResponseType.ExecutionStatus.Status.Failed;
                status.statusCodeData.subjectCode = "8.2.1";
                status.statusCodeData.subjectIdentifier = "3.9";
                status.statusCodeData.message = "Unknown ICCID";
                return null;
            }
            // Check if we are busy
            if (eis.verifyPendingProfileChangeTransaction(em)) {
                status.status = BaseResponseType.ExecutionStatus.Status.Failed;
                status.statusCodeData.subjectCode = "1.2";
                status.statusCodeData.subjectIdentifier = "4.4";
                status.statusCodeData.message = "Profile update in progress";
                return null;
            }


            if (profileInfo.getFallbackAttr()) {
                status.status = BaseResponseType.ExecutionStatus.Status.Failed;
                status.statusCodeData.subjectCode = "8.2.3";
                status.statusCodeData.subjectIdentifier = "3.8";
                status.statusCodeData.message = "Denied by FallBackAttr";
                return null;
            }
            // Check pol2
            try {
                List<Pol2Rule> pol2 = profileInfo.getPol2();
                Pol2Rule.Qualification q = Pol2Rule.qualificationAction(pol2, Pol2Rule.Action.DELETE);
                if (q != null && q == Pol2Rule.Qualification.NotAllowed) {
                    status.status = BaseResponseType.ExecutionStatus.Status.Failed;
                    status.statusCodeData.subjectCode = "8.2.3";
                    status.statusCodeData.subjectIdentifier = "3.8";
                    status.statusCodeData.message = "Denied by POL2";
                    return null;
                }
            } catch (Exception ex) {
            }

            // Make the transaction: If the profile is Enabled, first disable it. Then after that, delete it.
            ProfileInfo.State state = profileInfo.getState();
            BaseTransactionType st;

            if (state == ProfileInfo.State.Enabled) st = new DisableProfileTransaction(profileInfo, true);
            else st = new DeleteProfileTransaction(profileInfo);
            st.updateBaseData(senderEntity, receiverEntity, messageId, validityPeriod, replyTo, sender.getId());
            st.requestorType = sender.getType();
            SmSrTransaction transaction = new SmSrTransaction(em, messageType.value, messageId, receiverEntity, eid,
                    validityPeriod, false, st);
            em.persist(transaction);
            return transaction.getId();
        } catch (Exception ex) {
            Utils.lg.severe("Failed to create deleteProfile transaction: " + ex);
        }

        return null;
    }

    public static Long updateConnectivityParams(EntityManager em, RpaEntity sender, String eid,
                                                BaseResponseType.ExecutionStatus status, String iccid, String params,
                                                RpaEntity.Type senderType, WsaEndPointReference senderEntity,
                                                String receiverEntity, String messageId, long validityPeriod,
                                                WsaEndPointReference replyTo, Holder<String> messageType) {


        try {

            io.njiwa.sr.model.Eis eis = findAndCheckeUICC(em, eid, sender, status);

            ProfileInfo profileInfo = null;
            // Now check for one with matching ICCID
            try {
                Utils.Pair<Boolean, ProfileInfo> p = validateOwnerAction(eis, iccid, sender, status);
                profileInfo = p.l; // Find ICCID

                // Check ownership
                if (!p.k) return null;

                if (profileInfo.getState() != ProfileInfo.State.Enabled && profileInfo.getState() != ProfileInfo.State.Disabled) {
                    status.status = BaseResponseType.ExecutionStatus.Status.Failed;
                    status.statusCodeData.subjectCode = "8.2.1";
                    status.statusCodeData.subjectIdentifier = "1.2";
                    status.statusCodeData.message = "Profile state is wrong";
                    return null;
                }
            } catch (Exception ex) {
                status.status = BaseResponseType.ExecutionStatus.Status.Failed;
                status.statusCodeData.subjectCode = "8.2.1";
                status.statusCodeData.subjectIdentifier = "3.9";
                status.statusCodeData.message = "Unknown ICCID";
                return null;
            }

            // Make the transaction
            UpdateConnectivityParamsTransaction st = new UpdateConnectivityParamsTransaction(params);
            st.updateBaseData(senderEntity, receiverEntity, messageId, validityPeriod, replyTo, sender.getId());
            st.requestorType = senderType;
            SmSrTransaction transaction = new SmSrTransaction(em, messageType.value, messageId, receiverEntity, eid,
                    validityPeriod, false, st);
            transaction.setTargetAID(profileInfo.getIsd_p_aid()); // Set target so we send directly. Right?
            em.persist(transaction);
            return transaction.getId();
        } catch (Exception ex) {

            Utils.lg.severe(String.format("Error updating connectivity params: %s", ex));
        }

        return null;
    }

    public static Long disableProfile(EntityManager em, RpaEntity sender, String eid,
                                      BaseResponseType.ExecutionStatus status, String iccid,

                                       WsaEndPointReference senderEntity,
                                      String receiverEntity, String messageId, long validityPeriod,
                                      WsaEndPointReference replyTo, Holder<String> messageType) {
        try {
            // Find eis
            io.njiwa.sr.model.Eis eis = findAndCheckeUICC(em, eid, sender, status);
            Utils.Pair<Boolean, ProfileInfo> p = validateOwnerAction(eis, iccid, sender, status);
            ProfileInfo profileInfo = p.l;
            if (!p.k) return null;
            try {

                if (profileInfo.getState() != ProfileInfo.State.Enabled) {
                    status.status = BaseResponseType.ExecutionStatus.Status.Failed;
                    status.statusCodeData.subjectCode = "8.2.1";
                    status.statusCodeData.subjectIdentifier = "1.2";
                    status.statusCodeData.message = "Profile state is wrong";
                    return null;
                }
            } catch (Exception ex) {
                status.status = BaseResponseType.ExecutionStatus.Status.Failed;
                status.statusCodeData.subjectCode = "8.2.1";
                status.statusCodeData.subjectIdentifier = "3.9";
                status.statusCodeData.message = "Unknown ICCID";
                return null;
            }


            // Check pol2
            try {
                List<Pol2Rule> pol2 = profileInfo.getPol2();
                Pol2Rule.Qualification q = Pol2Rule.qualificationAction(pol2, Pol2Rule.Action.DISABLE);

                if (q != null && q == Pol2Rule.Qualification.NotAllowed) {
                    status.status = BaseResponseType.ExecutionStatus.Status.Failed;
                    status.statusCodeData.subjectCode = "8.2.3";
                    status.statusCodeData.subjectIdentifier = "3.8";
                    status.statusCodeData.message = "Denied by POL2";
                    return null;
                }
            } catch (Exception ex) {
            }

            // Make the transaction
            DisableProfileTransaction st = new DisableProfileTransaction(profileInfo, false);
            st.updateBaseData(senderEntity, receiverEntity, messageId, validityPeriod, replyTo, sender.getId());
            st.requestorType = sender.getType();
            SmSrTransaction transaction = new SmSrTransaction(em, messageType.value, messageId, receiverEntity, eid,
                    validityPeriod, false, st);
            em.persist(transaction);
            return transaction.getId();
        } catch (Exception ex) {
            Utils.lg.severe("Failed to disable profile: " + ex.getMessage());
        }

        return null;
    }

    public static Long enableProfile(EntityManager em, RpaEntity sender, String eid,
                                     BaseResponseType.ExecutionStatus status, String iccid,

                                      WsaEndPointReference senderEntity,
                                     String receiverEntity, String messageId, long validityPeriod,
                                     WsaEndPointReference replyTo, Holder<String> messageType) {
        try {
            // Find eis
            io.njiwa.sr.model.Eis eis = findAndCheckeUICC(em, eid, sender, status);
            Utils.Pair<Boolean, ProfileInfo> p = validateOwnerAction(eis, iccid, sender, status);
            ProfileInfo profileInfo = p.l;
            if (!p.k) return null;


            if (profileInfo.getState() != ProfileInfo.State.Disabled) {
                status.status = BaseResponseType.ExecutionStatus.Status.Failed;
                status.statusCodeData.subjectCode = "8.2.1";
                status.statusCodeData.subjectIdentifier = "1.2";
                status.statusCodeData.message = "Profile state is wrong";
                return null;
            }

            // Check if we are busy
            if (eis.verifyPendingProfileChangeTransaction(em)) {
                status.status = BaseResponseType.ExecutionStatus.Status.Failed;
                status.statusCodeData.subjectCode = "1.2";
                status.statusCodeData.subjectIdentifier = "4.4";
                status.statusCodeData.message = "Profile update in progress";
                return null;
            }

            // Check Pol2 of the one to be disabled
            try {
                ProfileInfo pActive = eis.findEnabledProfile();
                List<Pol2Rule> pol2 = pActive.getPol2();
                Pol2Rule.Qualification q = Pol2Rule.qualificationAction(pol2, Pol2Rule.Action.DISABLE);
                if (q != null && q == Pol2Rule.Qualification.NotAllowed) {
                    status.status = BaseResponseType.ExecutionStatus.Status.Failed;
                    status.statusCodeData.subjectCode = "8.2.2";
                    status.statusCodeData.subjectIdentifier = "3.8";
                    status.statusCodeData.message = "Denied by POL2 of active ISDP";
                    return null;
                }
            } catch (Exception ex) {

            }
            // Then check our pol2 rules...
            try {
                List<Pol2Rule> pol2 = profileInfo.getPol2();
                Pol2Rule.Qualification q = Pol2Rule.qualificationAction(pol2, Pol2Rule.Action.ENABLE);

                if (q != null && q == Pol2Rule.Qualification.NotAllowed) {
                    status.status = BaseResponseType.ExecutionStatus.Status.Failed;
                    status.statusCodeData.subjectCode = "8.2.3";
                    status.statusCodeData.subjectIdentifier = "3.8";
                    status.statusCodeData.message = "Denied by POL2";
                    return null;
                }
            } catch (Exception ex) {
            }

            // Make the transaction
            EnableProfileTransaction st = new EnableProfileTransaction(profileInfo);
            st.updateBaseData(senderEntity, receiverEntity, messageId, validityPeriod, replyTo, sender.getId());
            SmSrTransaction transaction = new SmSrTransaction(messageType.value, messageId, receiverEntity,
                    eis.getId(), validityPeriod, false, st);
            em.persist(transaction);
            return transaction.getId();

        } catch (Exception ex) {
            Utils.lg.severe("Failed to enable profile: " + ex.getMessage());

        }

        return null;
    }

    public static Eis getEIS(EntityManager em, String eid, RpaEntity.Type senderType, RpaEntity sender,
                             BaseResponseType.ExecutionStatus status) {
        Eis eis = null;

        if (senderType != sender.getType()) {
            status.status = BaseResponseType.ExecutionStatus.Status.Failed;
            status.statusCodeData.reasonCode = "1.1";
            status.statusCodeData.subjectIdentifier = "EID";
            status.statusCodeData.subjectCode = "8.6";
            status.statusCodeData.message = "Not allowed";
            return null;
        }
        try {
            io.njiwa.sr.model.Eis xeis = io.njiwa.sr.model.Eis.findByEid(em, eid);
            eis = xeis == null || xeis.getRegistrationComplete() != true ? null : Eis.fromModel(xeis);
            eis.hideGetEISFields(sender.getOid(), senderType);
        } catch (Exception ex) {
        }

        if (eis == null) {
            status.status = BaseResponseType.ExecutionStatus.Status.Failed;
            status.statusCodeData.reasonCode = "1.1";
            status.statusCodeData.subjectIdentifier = "EID";
            status.statusCodeData.subjectCode = "8.1.1";
            status.statusCodeData.message = "Unknown EID";
        }
        return eis;
    }


    public static Long createISDP(EntityManager em, String eid, BaseResponseType.ExecutionStatus status,
                                  String iccid, String mnoId,
                                  WsaEndPointReference senderEntity,
                                  String receiverEntity, String messageId, long validityPeriod,
                                  WsaEndPointReference replyTo, Holder<String> messageType,
                                  int requiredMem, boolean more,
                                  RpaEntity sender)
    {
        // Find eis
        io.njiwa.sr.model.Eis eis = io.njiwa.sr.model.Eis.findByEid(em, eid);
        // Check for pending euicc handover
        if (eis.verifyPendingEuiCCHandoverTransaction(em)) {
            status.status = BaseResponseType.ExecutionStatus.Status.Failed;
            status.statusCodeData.subjectCode = "1.2";
            status.statusCodeData.reasonCode = "4.4";
            status.statusCodeData.message = "EIS busy: Handover in progress";
            return null;
        }
        // Now check for one with matching ICCID
        try {
            for (ProfileInfo p : eis.getProfiles())
                if (p.getIccid().equalsIgnoreCase(iccid)) {
                    status.status = BaseResponseType.ExecutionStatus.Status.Failed;
                    status.statusCodeData.subjectCode = "8.2.1";
                    status.statusCodeData.reasonCode = "3.3";
                    status.statusCodeData.message = "ICCID in use";
                    return null;
                }
        } catch (Exception ex) {

        }
        // Check for sufficient memory
        try {
            int mem = requiredMem;
            for (ProfileInfo p : eis.getProfiles())
                mem += p.getAllocatedMemory();
            if (mem >= eis.getAvailableMemoryForProfiles()) {
                status.status = BaseResponseType.ExecutionStatus.Status.Failed;
                status.statusCodeData.subjectCode = "8.1";
                status.statusCodeData.subjectIdentifier = "4.8";
                status.statusCodeData.message = "insufficient memory";
                return null;
            }
        } catch (Exception ex) {

        }
        // Add it
        try {
            ProfileInfo newProfile = eis.addNewProfile(iccid, mnoId, requiredMem, sender.getOid());
            em.persist(newProfile); // Save it
            CreateISDPTransaction st = new CreateISDPTransaction(eis, newProfile);

            st.updateBaseData(senderEntity, receiverEntity, messageId, validityPeriod, replyTo, sender.getId());
            SmSrTransaction transaction = new SmSrTransaction(em, messageType.value, messageId, receiverEntity, eid, validityPeriod, more, st);
            em.persist(transaction);
            return transaction.getId();
        } catch (Exception ex) {
            Utils.lg.warning(String.format("Failed to create ISDP [%s] on eis [%s]: %s", iccid,eid,ex));
            return null;
        }

    }

    public static boolean profileDownloadComplete(EntityManager em,
                                                  BaseResponseType.ExecutionStatus status,
                                                  RpaEntity sender,
                                                  String eid,
                                                  String iccid, String profileType, SubscriptionAddress subscriptionAddress,
                                                  Pol2Type pol2)
    {
        try {
            // Find eis
            io.njiwa.sr.model.Eis eis = findAndCheckeUICC(em,eid,sender,status);
            if (eis == null)
                return false;
            Utils.Pair<Boolean, ProfileInfo> px = validateOwnerAction(eis,iccid,sender,status);
            ProfileInfo p = px.l;

            if (p == null)
                return false;

            if (p.getState() != ProfileInfo.State.Created) {
                status.statusCodeData.subjectCode = "8.2.1";
                status.statusCodeData.reasonCode = "1.2";
                status.statusCodeData.subjectIdentifier = "Profile ICCID";
                status.statusCodeData.message = "Wrong profile state!";
                return false;
            }
            if (profileType != null)
                p.setProfileType(profileType);
            if (pol2 != null)
                pol2.toModel(p);
            if (subscriptionAddress != null) {
                // XX Should we check for duplicates?
                p.setMsisdn(subscriptionAddress.msisdn);
                p.setImsi(subscriptionAddress.imsi);
            }
            p.setState(ProfileInfo.State.Disabled); // State changes to disabled as per spec.
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    public static Long sendData(EntityManager em,
                                WsaEndPointReference senderEntity,
                                WsaEndPointReference replyTo,
                                String eid, String msgType, String aid,String data,
                                boolean hasMore, String messageId, long validityPeriod,
                                String receiverEntity,
                                RpaEntity sender,
                                BaseResponseType.ExecutionStatus status)
    {
        final SendDataTransaction st = new SendDataTransaction();
        st.status = status; // Copy it.
        try {
            st.updateBaseData(senderEntity,receiverEntity,messageId,validityPeriod,replyTo,sender.getId());
            st.cAPDUs = SDCommand.deconstruct(data);
            SmSrTransaction t = new SmSrTransaction(em, msgType, messageId,
                    receiverEntity, eid, validityPeriod, hasMore, st);
            t.setTargetAID(aid); // Record AID
            // Validate sd-aid: look for it
            long eisId = t.getEis_id();

            io.njiwa.sr.model.Eis xEis = em.find(io.njiwa.sr.model.Eis.class, eisId);
            // Look for it by sd-aid
            boolean foundSd = false;
            List<ProfileInfo> pl = xEis.getProfiles();
            List<SecurityDomain> sl = xEis.getSdList();
            if (pl != null)
                for (ProfileInfo p : pl)
                    if (p.getIsd_p_aid() != null && aid.equalsIgnoreCase(p.getIsd_p_aid())) {
                        foundSd = true;
                        break;
                    }
            if (sl != null && !foundSd)
                for (SecurityDomain s : sl)
                    if (s.getAid() != null && aid.equalsIgnoreCase(s.getAid())) {
                        foundSd = true;
                        break;
                    }
            if (!foundSd) {
                status.status = BaseResponseType.ExecutionStatus.Status.Failed;
                status.statusCodeData = new BaseResponseType.ExecutionStatus.StatusCode("8.3.1", "3.9",
                        "Unknown " +
                                "ISD-P/ISD-R", "SendData");
                return null;
            } else {
                st.status = null; // Clear it
                em.persist(t);
                return t.getId();
            }
        } catch (Exception ex){
            Utils.lg.severe("Failed to send data: " + ex);
            return null;
        }
    }

    public static void sendDisableProfileResponse(EntityManager em, BaseTransactionType tr, byte[] response) {
        Utils.Pair<WsaEndPointReference, WsaEndPointReference> p = tr.markTransactionEnded(em);
        try {
            String resp = response != null ? Utils.HEX.b2H(response) : null;
            String msgURI = tr.requestorType == RpaEntity.Type.SMDP ? "http://gsma" + ".com/ES3" +
                    "/ProfileManagentCallBack/ES3-DisableProfile" : "http://gsma" + ".com/ES4/ProfileManagentCallBack"
                    + "/ES4-DisableProfile";
            final Holder<String> msgType = new Holder<String>(msgURI);
            if (tr.requestorType == RpaEntity.Type.SMDP) {
                if (tr.requestingEntityId == RpaEntity.LOCAL_ENTITY_ID)
                    io.njiwa.dp.ws.CommonImpl.ISDPstatusChangeresponseHandler(em,tr.relatesTO,
                            ChangeProfileStatusTransaction.Action.DISABLE,tr.status,resp);
                else {
                    ES3 proxy = WSUtils.getPort("http://namespaces.gsma.org/esim-messaging/1", "ES3Port", p.k, ES3.class, RpaEntity.Type.SMSR, em, tr.requestingEntityId);
                    proxy.disableProfileResponse(p.l, p.k.address, tr.relatesTO, msgType, Utils.gregorianCalendarFromDate(tr.startDate), Utils.gregorianCalendarFromDate(tr.endDate), TransactionType.DEFAULT_VALIDITY_PERIOD, tr.status, resp);
                }
            } else {
                ES4 proxy = WSUtils.getPort("http://namespaces.gsma.org/esim-messaging/1", "ES4Port", p.k, ES4.class,
                        RpaEntity.Type.SMSR, em, tr.requestingEntityId);
                proxy.disableProfileResponse(p.l, p.k.address, tr.relatesTO, msgType,
                        Utils.gregorianCalendarFromDate(tr.startDate), Utils.gregorianCalendarFromDate(tr.endDate),
                        TransactionType.DEFAULT_VALIDITY_PERIOD, tr.status, resp);
            }
        } catch (WSUtils.SuppressClientWSRequest s) {
        } catch (Exception ex) {
            Utils.lg.severe("Failed to issue async DisableProfile response call: " + ex.getMessage());
        }
    }


    public static void sendAuditEISResponse(EntityManager em, BaseTransactionType tr, io.njiwa.sr.model.Eis xeis,
                                            List<String> iccids, RpaEntity requestor) {
        Utils.Pair<WsaEndPointReference, WsaEndPointReference> p = tr.markTransactionEnded(em);

        try {
            Eis eis = Eis.fromModel(xeis);
            eis.hideGetEISFields(requestor.getOid(), tr.requestorType, iccids);
            String msgUri = tr.requestorType == RpaEntity.Type.SMDP ? "http://gsma" + ".com/ES3" +
                    "/ProfileManagentCallBack/ES3-AuditEIS" :
                    "http://gsma" + ".com/ES4/ProfileManagentCallBack/ES4" + "-AuditEIS";
            Holder<String> msgType = new Holder<>(msgUri);
            if (tr.requestorType == RpaEntity.Type.SMDP) {
                ES3 proxy = WSUtils.getPort("http://namespaces.gsma.org/esim-messaging/1", "ES3Port", p.k, ES3.class,
                        RpaEntity.Type.SMSR, em, tr.requestingEntityId);
                proxy.auditEISResponse(p.l, p.k.makeAddress(), tr.relatesTO, msgType,
                        Utils.gregorianCalendarFromDate(tr.startDate), Utils.gregorianCalendarFromDate(tr.endDate),
                        TransactionType.DEFAULT_VALIDITY_PERIOD, tr.status, eis);
            } else {
                ES4 proxy = WSUtils.getPort("http://namespaces.gsma.org/esim-messaging/1", "ES3Port", p.k, ES4.class,
                        RpaEntity.Type.SMSR, em, tr.requestingEntityId);
                proxy.auditEISResponse(p.l, p.k.makeAddress(), tr.relatesTO, msgType,
                        Utils.gregorianCalendarFromDate(tr.startDate), Utils.gregorianCalendarFromDate(tr.endDate),
                        TransactionType.DEFAULT_VALIDITY_PERIOD, tr.status, eis);
            }
        } catch (Exception ex) {

        }
    }

    public static void sendDeleteProfileResponse(EntityManager em, BaseTransactionType tr, byte[] response) {
        Utils.Pair<WsaEndPointReference, WsaEndPointReference> p = tr.markTransactionEnded(em);

        try {
            String resp = response != null ? Utils.HEX.b2H(response) : null;

            String msgUri = tr.requestorType == RpaEntity.Type.SMDP ? "http://gsma" + ".com/ES3" +
                    "/ProfileManagentCallBack/ES3-DeleteISDP" : "http://gsma" + ".com/ES4/ProfileManagentCallBack/ES4"
                    + "-DeleteProfile";
            Holder<String> msgType = new Holder<String>(msgUri);
            if (tr.requestorType == RpaEntity.Type.SMDP) {
                if (tr.requestingEntityId == RpaEntity.LOCAL_ENTITY_ID) {
                    io.njiwa.dp.ws.CommonImpl.ISDPstatusChangeresponseHandler(em,tr.relatesTO,
                            ChangeProfileStatusTransaction.Action.DELETE,tr.status,resp);
                } else {
                    ES3 proxy = WSUtils.getPort("http://namespaces.gsma.org/esim-messaging/1", "ES3Port", p.k, ES3.class, RpaEntity.Type.SMSR, em, tr.requestingEntityId);
                    proxy.deleteISDPResponse(p.l, p.k.address, tr.relatesTO, msgType, Utils.gregorianCalendarFromDate(tr.startDate), Utils.gregorianCalendarFromDate(tr.endDate), TransactionType.DEFAULT_VALIDITY_PERIOD, tr.status, resp);
                }
            } else {
                ES4 proxy = WSUtils.getPort("http://namespaces.gsma.org/esim-messaging/1", "ES4Port", p.k, ES4.class,
                        RpaEntity.Type.SMSR, em, tr.requestingEntityId);
                proxy.deleteISDPResponse(p.l, p.k.address, tr.relatesTO, msgType,
                        Utils.gregorianCalendarFromDate(tr.startDate), Utils.gregorianCalendarFromDate(tr.endDate),
                        TransactionType.DEFAULT_VALIDITY_PERIOD, tr.status, resp);
            }

        } catch (WSUtils.SuppressClientWSRequest s) {
            String xs = null;
        } catch (Exception ex) {
            Utils.lg.severe("Failed to issue async DeleteISDP response call: " + ex.getMessage());
        }
    }

    public static void sendEnableProfileResponse(EntityManager em, BaseTransactionType tr, byte[] response) {
        Utils.Pair<WsaEndPointReference, WsaEndPointReference> p = tr.markTransactionEnded(em);

        try {
            String resp = response != null ? Utils.HEX.b2H(response) : null;

            String msgUri = tr.requestorType == RpaEntity.Type.SMDP ? "http://gsma" + ".com/ES3" +
                    "/ProfileManagentCallBack/ES3-EnableProfile" :
                    "http://gsma" + ".com/ES4/ProfileManagentCallBack" + "/ES4-EnableProfile";
            Holder<String> msgType = new Holder<>(msgUri);
            if (tr.requestorType == RpaEntity.Type.SMDP) {
                if (tr.requestingEntityId == RpaEntity.LOCAL_ENTITY_ID)
                    io.njiwa.dp.ws.CommonImpl.ISDPstatusChangeresponseHandler(em,tr.relatesTO,
                            ChangeProfileStatusTransaction.Action.ENABLE,tr.status,resp);
                else {
                    ES3 proxy = WSUtils.getPort("http://namespaces.gsma.org/esim-messaging/1", "ES3Port", p.k, ES3.class, RpaEntity.Type.SMSR, em, tr.requestingEntityId);
                    proxy.enableProfileResponse(p.l, p.k.address, tr.relatesTO, msgType, Utils.gregorianCalendarFromDate(tr.startDate), Utils.gregorianCalendarFromDate(tr.endDate), TransactionType.DEFAULT_VALIDITY_PERIOD, tr.status, resp);
                }
            } else {
                ES4 proxy = WSUtils.getPort("http://namespaces.gsma.org/esim-messaging/1", "ES4Port", p.k, ES4.class,
                        RpaEntity.Type.SMSR, em, tr.requestingEntityId);
                proxy.enableProfileResponse(p.l, p.k.address, tr.relatesTO, msgType,
                        Utils.gregorianCalendarFromDate(tr.startDate), Utils.gregorianCalendarFromDate(tr.endDate),
                        TransactionType.DEFAULT_VALIDITY_PERIOD, tr.status, resp);
            }
        } catch (WSUtils.SuppressClientWSRequest s) {
        } catch (Exception ex) {
            Utils.lg.severe("Failed to issue async EnableProfile response call: " + ex.getMessage());
        }
    }

    public static Utils.Triple<BaseResponseType.ExecutionStatus, RpaEntity, Date> makeBaseResp(WebServiceContext context, String subjectCode) {
        final RpaEntity sender = Authenticator.getUser(context); // Get the sender
        return makeBaseResp(sender,subjectCode);
    }

    public static Utils.Triple<BaseResponseType.ExecutionStatus, RpaEntity, Date> makeBaseResp(RpaEntity sender, String subjectCode) {
        Date startDate = Calendar.getInstance().getTime();
        BaseResponseType.ExecutionStatus.Status status = BaseResponseType.ExecutionStatus.Status.ExecutedSuccess;
        final BaseResponseType.ExecutionStatus.StatusCode statusCode =
                new BaseResponseType.ExecutionStatus.StatusCode("8" + ".1.1", subjectCode, "", "");
        final BaseResponseType.ExecutionStatus st = new BaseResponseType.ExecutionStatus(status, statusCode);
        return new Utils.Triple<>(st, sender, startDate);
    }
}
