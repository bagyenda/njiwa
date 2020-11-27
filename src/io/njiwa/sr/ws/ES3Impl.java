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

import io.njiwa.common.PersistenceUtility;
import io.njiwa.common.SDCommand;
import io.njiwa.common.Utils;
import io.njiwa.common.model.RpaEntity;
import io.njiwa.common.ws.WSUtils;
import io.njiwa.common.ws.handlers.Authenticator;
import io.njiwa.common.ws.types.BaseResponseType;
import io.njiwa.common.ws.types.WsaEndPointReference;
import io.njiwa.sr.model.Eis;
import io.njiwa.sr.model.ProfileInfo;
import io.njiwa.sr.model.SecurityDomain;
import io.njiwa.sr.model.SmSrTransaction;
import io.njiwa.sr.transactions.CreateISDPTransaction;
import io.njiwa.sr.transactions.SendDataTransaction;
import io.njiwa.sr.ws.types.*;

import javax.annotation.Resource;
import javax.ejb.Stateless;
import javax.inject.Inject;
import javax.jws.*;
import javax.jws.soap.SOAPBinding;
import javax.persistence.EntityManager;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;
import javax.xml.ws.Action;
import javax.xml.ws.Holder;
import javax.xml.ws.WebServiceContext;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

/**
 * Created by bagyenda on 08/06/2016.
 */


// Sending of 202 response for Accept, according to:
// http://stackoverflow.com/questions/19297722/how-to-make-jax-ws-webservice-respond-with-specific-http-code
@WebService(name = "ES3", serviceName = Authenticator.SMSR_SERVICE_NAME, targetNamespace = "http://namespaces.gsma.org/esim-messaging/1")
@SOAPBinding(style = SOAPBinding.Style.RPC, use = SOAPBinding.Use.LITERAL)
@Stateless
@HandlerChain(file = "../../common/ws/handlers/ws-default-handler-chain.xml")
public class ES3Impl {

    @Inject
    PersistenceUtility po; // For saving objects
    @Resource
    private WebServiceContext context;


    @WebMethod(operationName = "GetEIS")
    @Action(input = "http://gsma.com/ES3/ProfileManagent/ES3-GetEISRequest",
            output = "http://gsma.com/ES3/ProfileManagent/ES3-GetEISResponse")
    @WebResult(name = "FunctionExecutionStatus")
    public GetEISResponse getEIS(@WebParam(name = "From", header = true, targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                    WsaEndPointReference senderEntity,

                                 @WebParam(name = "To", header = true, targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                    String receiverEntity,
                                 @WebParam(name = "ReplyTo", header = true, targetNamespace = "http://www.w3" +
                                            ".org/2007/05/addressing/metadata")
                                    WsaEndPointReference replyTo,
                                 @WebParam(name = "MessageID", header = true,
                                            targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                    String messageId,
                                 // WSA: Action
                                 @WebParam(name = "Action", header = true, mode = WebParam.Mode.INOUT,
                                            targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                    Holder<String> messageType,

                                 // These are in the body
                                 @WebParam(name = "FunctionCallIdentifier")
                                    String functionCallId,

                                 @WebParam(name = "ValidityPeriod")
                                    long validityPeriod,

                                 @WebParam(name = "Eid")
                                    final String eid,
                                 @WebParam(name = "RelatesTo", mode = WebParam.Mode.OUT, header = true,
                                            targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                    Holder<String> relatesTo
    ) {
        relatesTo.value = messageId;
        messageType.value = "http://gsma.com/ES3/ProfileManagent/ES3-GetEISResponse";
        final RpaEntity sender = Authenticator.getUser(context); // Get the sender
        Date startDate = Calendar.getInstance().getTime();
        BaseResponseType.ExecutionStatus.Status status = BaseResponseType.ExecutionStatus.Status.ExecutedSuccess;
        final BaseResponseType.ExecutionStatus.StatusCode statusCode = new BaseResponseType.ExecutionStatus.StatusCode("8" +
                ".1.1", "GetEIS", "", "");
        BaseResponseType.ExecutionStatus st = new BaseResponseType.ExecutionStatus(status,
                statusCode);
        io.njiwa.sr.ws.types.Eis eis = CommonImpl.getEIS(po, eid, RpaEntity.Type.SMDP, sender, st);
        return new GetEISResponse(startDate, Calendar.getInstance().getTime(), validityPeriod,
                st, eis);
    }
    @WebMethod(operationName = "AuditEIS")
    @Action(input = "http://gsma.com/ES3/ProfileManagent/ES3-AuditEIS",
            output = "http://gsma.com/ES3/ProfileManagentCallback/ES3-AuditEIS")
    @WebResult(name = "FunctionExecutionStatus")
  public AuditEISResponse auditEIS(@WebParam(name = "From", header = true, targetNamespace = "http://www.w3" +
            ".org/2007/05/addressing/metadata")
                              WsaEndPointReference senderEntity,

                                   @WebParam(name = "To", header = true, targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                              String receiverEntity,
                                   @WebParam(name = "ReplyTo", header = true, targetNamespace = "http://www.w3" +
                                      ".org/2007/05/addressing/metadata")
                              WsaEndPointReference replyTo,
                                   @WebParam(name = "MessageID", header = true,
                                      targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                              String messageId,
                                   // WSA: Action
                                   @WebParam(name = "Action", header = true, mode = WebParam.Mode.INOUT,
                                      targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                              Holder<String> messageType,

                                   // These are in the body
                                   @WebParam(name = "FunctionCallIdentifier")
                              String functionCallId,

                                   @WebParam(name = "ValidityPeriod")
                              long validityPeriod,

                                   @WebParam(name = "Eid")
                              final String eid,
                                   @WebParam(name = "RelatesTo", mode = WebParam.Mode.OUT, header = true,
                                      targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                              Holder<String> relatesTo
    ) throws Exception {

        Date startDate = Calendar.getInstance().getTime();
        HttpServletResponse resp = WSUtils.getRespObject(context);
        final RpaEntity sender = Authenticator.getUser(context); // Get the sender

        final BaseResponseType.ExecutionStatus status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.ExecutedSuccess, new BaseResponseType.ExecutionStatus.StatusCode("8" +
                ".1.1", "AuditEIS", "", ""));
        Long tr = CommonImpl.auditEIS(po,sender,eid,null,status, RpaEntity.Type.SMDP,senderEntity,receiverEntity,
                messageId,validityPeriod,replyTo,messageType);
        if (tr == null)
             return new AuditEISResponse(startDate,Calendar.getInstance().getTime(),validityPeriod,status,null);
        resp.sendError(Response.Status.ACCEPTED.getStatusCode(), "");
        return new AuditEISResponse(startDate,Calendar.getInstance().getTime(),validityPeriod,status,null);
    }

    @WebMethod(operationName = "SendData")
    @Action(input = "http://gsma.com/ES3/ProfileManagent/ES3-SendData")
    public SendDataResponse sendData(@WebParam(name = "From", header = true, targetNamespace = "http://www.w3" +
            ".org/2007/05/addressing/metadata")
                                     WsaEndPointReference senderEntity,

                                     @WebParam(name = "To", header = true, targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                     final String receiverEntity,
                                     @WebParam(name = "ReplyTo", header = true, targetNamespace = "http://www.w3" +
                                             ".org/2007/05/addressing/metadata")
                                     WsaEndPointReference replyTo,
                                     @WebParam(name = "MessageID", header = true,
                                             targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                     final String messageId,
                                     // WSA: Action
                                     @WebParam(name = "Action", header = true, mode = WebParam.Mode.INOUT,
                                             targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                     final Holder<String> messageType,

                                     // These are in the body
                                     @WebParam(name = "FunctionCallIdentifier")
                                     String functionCallId,

                                     @WebParam(name = "ValidityPeriod")
                                     final long validityPeriod,

                                     @WebParam(name = "Eid")
                                     final String eid,
                                     @WebParam(name = "sd-aid")
                                     final String aid,
                                     @WebParam(name = "Data")
                                     final String data,

                                     @WebParam(name = "moreToDo")
                                     final boolean more,
                                     @WebParam(name = "RelatesTo", mode = WebParam.Mode.OUT, header = true,
                                             targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                     Holder<String> relatesTo
    ) throws Exception {
        // Send 202 response for Accept, according to:
        // http://stackoverflow.com/questions/19297722/how-to-make-jax-ws-webservice-respond-with-specific-http-code
        HttpServletResponse resp = WSUtils.getRespObject(context);

        Date startTime = Calendar.getInstance().getTime();
        final BaseResponseType.ExecutionStatus status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.ExecutedSuccess, new BaseResponseType.ExecutionStatus.StatusCode("8" +
                ".1.1", "SendData", "", ""));
        String msg;
        final SendDataTransaction st = new SendDataTransaction();
        st.status = status; // Copy it.

        st.updateBaseData(senderEntity, receiverEntity, messageId, validityPeriod, replyTo, Authenticator
                .getUser(context).getId());
        Long tr = null;
        try {
            st.sdAid = aid;
            st.cAPDUs = SDCommand.deconstruct(data);

            tr = (Long) po.doTransaction(new PersistenceUtility.Runner() {
                @Override
                public Object run(PersistenceUtility po, EntityManager em) throws Exception {
                    SmSrTransaction t = new SmSrTransaction(em, messageType.value, messageId,
                            receiverEntity, eid, validityPeriod, more, st);
                    t.setTargetAID(aid); // Record AID
                    // Validate sd-aid
                    long eisId = t.getEis_id();

                    Eis xEis = em.find(Eis.class, eisId);
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
                }

                @Override
                public void cleanup(boolean success) {

                }
            });
            msg = tr == null ? "Error" : "";
            // HTTP Accept
        } catch (Exception ex) {
            msg = "Error: " + ex.getMessage();
        }

        if (tr == null)  // WE had an error, send response
            return new SendDataResponse(startTime, Calendar.getInstance().getTime(), validityPeriod, status, null);
        else
            resp.sendError(Response.Status.ACCEPTED.getStatusCode(), msg);
        return null; // Because we have sent an HTTP response
    }

    @WebMethod(operationName = "ProfileDownloadCompleted")
    @Action(input = "http://gsma.com/ES3/ProfileManagent/ES3-ProfileDownloadCompleted")
    public BaseResponseType profileDownloadCompleted(@WebParam(name = "From", header = true,
            targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                                     WsaEndPointReference senderEntity,

                                                     @WebParam(name = "To", header = true, targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                                     final String receiverEntity,
                                                     @WebParam(name = "ReplyTo", header = true, targetNamespace = "http://www.w3" +
                                                             ".org/2007/05/addressing/metadata")
                                                     WsaEndPointReference replyTo,
                                                     @WebParam(name = "MessageID", header = true,
                                                             targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                                     final String messageId,
                                                     // WSA: Action
                                                     @WebParam(name = "Action", header = true, mode = WebParam.Mode.INOUT,
                                                             targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                                     final Holder<String> messageType,

                                                     // These are in the body
                                                     @WebParam(name = "FunctionCallIdentifier")
                                                     String functionCallId,

                                                     @WebParam(name = "ValidityPeriod")
                                                     final long validityPeriod,

                                                     @WebParam(name = "Eid")
                                                     final String eid,
                                                     @WebParam(name = "Iccid")
                                                     final String iccid,
                                                     @WebParam(name = "ProfileType")
                                                     final String profileType,
                                                     @WebParam(name = "SubscriptionAddress")
                                                     final SubscriptionAddress subscriptionAddress,
                                                     @WebParam(name = "pol2")
                                                     final Pol2Type pol2) {
        Date startDate = Calendar.getInstance().getTime();

        final BaseResponseType.ExecutionStatus.StatusCode code = new BaseResponseType.ExecutionStatus.StatusCode();
        code.subjectCode = "8.1.1";
        code.reasonCode = "";
        code.message = "";
        code.subjectIdentifier = "";

        boolean t = po.doTransaction(new PersistenceUtility.Runner<Boolean>() {
            @Override
            public Boolean run(PersistenceUtility po, EntityManager em) throws Exception {
                // Find eis
                Eis eis = Eis.findByEid(em, eid);
                if (eis == null) {
                    code.subjectIdentifier = "EID";
                    code.subjectCode = "8.1.1";
                    code.reasonCode = "3.9";
                    code.message = "Unknown EID";
                    return false;
                }
                ProfileInfo p = eis.findProfileByICCID(iccid);
                if (p == null) {
                    code.subjectCode = "8.2.1";
                    code.reasonCode = "3.9";
                    code.subjectIdentifier = "Profile ICCID";
                    code.message = "Unknown profile for given EID";
                    return false;
                }
                if (p.getState() != ProfileInfo.State.Created) {
                    code.subjectCode = "8.2.1";
                    code.reasonCode = "1.2";
                    code.subjectIdentifier = "Profile ICCID";
                    code.message = "Wrong profile state!";
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
                p.setState(ProfileInfo.State.Disabled); // State changes to disabled...
                return true;
            }

            @Override
            public void cleanup(boolean success) {

            }
        });


        BaseResponseType.ExecutionStatus.Status status = Utils.toBool(t) ? BaseResponseType.ExecutionStatus.Status
                .ExecutedSuccess
                : BaseResponseType.ExecutionStatus.Status.Failed;
        BaseResponseType.ExecutionStatus executionStatus = new BaseResponseType.ExecutionStatus(status, code);
        Date endDate = Calendar.getInstance().getTime();

        BaseResponseType resp = new BaseResponseType(startDate, endDate, validityPeriod, executionStatus);
        return resp;
    }

    @WebMethod(operationName = "UpdatePolicyRules")
    @Action(input = "http://gsma.com/ES3/ProfileManagent/ES3-UpdatePolicyRules")
    public BaseResponseType updatePolicyRules(@WebParam(name = "From", header = true,
            targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                              WsaEndPointReference senderEntity,

                                              @WebParam(name = "To", header = true, targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                              final String receiverEntity,
                                              @WebParam(name = "ReplyTo", header = true, targetNamespace = "http://www.w3" +
                                                      ".org/2007/05/addressing/metadata")
                                              WsaEndPointReference replyTo,
                                              @WebParam(name = "MessageID", header = true,
                                                      targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                              final String messageId,
                                              // WSA: Action
                                              @WebParam(name = "Action", header = true, mode = WebParam.Mode.INOUT,
                                                      targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                              final Holder<String> messageType,

                                              // These are in the body
                                              @WebParam(name = "FunctionCallIdentifier")
                                              String functionCallId,

                                              @WebParam(name = "ValidityPeriod")
                                              final long validityPeriod,

                                              @WebParam(name = "Eid")
                                              final String eid,
                                              @WebParam(name = "Iccid")
                                              final String iccid,
                                              @WebParam(name = "pol2")
                                              final Pol2Type pol2) {
        final RpaEntity sender = Authenticator.getUser(context); // Get the sender
        return CommonImpl.updatePolicyRules(po, sender, eid, iccid, pol2, RpaEntity.Type.SMDP);
    }

    @WebMethod(operationName = "CreateISDP")
    @Action(input = "http://gsma.com/ES3/ProfileManagent/ES3-CreateISDP")
    public CreateISDPResponse createISDP(@WebParam(name = "From", header = true,
            targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                         final WsaEndPointReference senderEntity,

                                         @WebParam(name = "To", header = true, targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                         final String receiverEntity,
                                         @WebParam(name = "ReplyTo", header = true, targetNamespace = "http://www.w3" +
                                                 ".org/2007/05/addressing/metadata")
                                         final WsaEndPointReference replyTo,
                                         @WebParam(name = "MessageID", header = true,
                                                 targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                         final String messageId,
                                         // WSA: Action
                                         @WebParam(name = "Action", header = true, mode = WebParam.Mode.INOUT,
                                                 targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                         final Holder<String> messageType,

                                         // These are in the body
                                         @WebParam(name = "FunctionCallIdentifier")
                                         String functionCallId,

                                         @WebParam(name = "ValidityPeriod")
                                         final long validityPeriod,

                                         @WebParam(name = "Eid")
                                         final String eid,
                                         @WebParam(name = "Iccid")
                                         final String iccid,
                                         @WebParam(name = "Mno-id")
                                         final String mnoId,

                                         @WebParam(name = "RequiredMemory")
                                         final int requiredMem,

                                         @WebParam(name = "moreToDo")
                                         final boolean more,
                                         @WebParam(name = "RelatesTo", mode = WebParam.Mode.OUT, header = true,
                                                 targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                         Holder<String> relatesTo
    ) throws Exception {

        // Send 202 response for Accept, according to:
        // http://stackoverflow.com/questions/19297722/how-to-make-jax-ws-webservice-respond-with-specific-http-code
        HttpServletResponse resp = WSUtils.getRespObject(context);

        String msg = "";
        final BaseResponseType.ExecutionStatus status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.ExecutedSuccess,
                new BaseResponseType.ExecutionStatus.StatusCode("8" +
                        ".1.1", "CreateISDP", "", ""));
        Date startTime = Calendar.getInstance().getTime();
        Long tr;

        try {

            tr = po.doTransaction(new PersistenceUtility.Runner<Long>() {
                @Override
                public Long run(PersistenceUtility po, EntityManager em) throws Exception {
                    // Find eis
                    Eis eis = Eis.findByEid(em, eid);
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
                    ProfileInfo newProfile = eis.addNewProfile(iccid, mnoId, requiredMem, getSenderSMDP());
                    em.persist(newProfile); // Save it
                    CreateISDPTransaction st = new CreateISDPTransaction(eis, newProfile);

                    st.updateBaseData(senderEntity, receiverEntity, messageId, validityPeriod, replyTo, Authenticator
                            .getUser(context).getId());
                    SmSrTransaction transaction = new SmSrTransaction(em, messageType.value, messageId,
                            receiverEntity, eid, validityPeriod, more, st);
                    em.persist(transaction);
                    return transaction.getId();
                }

                @Override
                public void cleanup(boolean success) {

                }
            });
        } catch (Exception ex) {
            tr = null;
            msg = String.format("Failed to execute: %s", ex);
        }

        if (tr == null)  // WE had an error, do the async call back immediately
            return new CreateISDPResponse(startTime, Calendar.getInstance().getTime(), validityPeriod, status, null, null);
        else
            resp.sendError(Response.Status.ACCEPTED.getStatusCode(), msg);
        return null;
    }

    @WebMethod(operationName = "EnableProfile")
    @Action(input = "http://gsma.com/ES3/ProfileManagent/ES3-EnableProfile")
    public EnableProfileResponse enableProfile(@WebParam(name = "From", header = true,
            targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                               final WsaEndPointReference senderEntity,

                                               @WebParam(name = "To", header = true, targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                               final String receiverEntity,
                                               @WebParam(name = "ReplyTo", header = true, targetNamespace = "http://www.w3" +
                                                       ".org/2007/05/addressing/metadata") final
                                               WsaEndPointReference replyTo,
                                               @WebParam(name = "MessageID", header = true,
                                                       targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                               final String messageId,
                                               // WSA: Action
                                               @WebParam(name = "Action", header = true, mode = WebParam.Mode.INOUT,
                                                       targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                               final Holder<String> messageType,

                                               // These are in the body
                                               @WebParam(name = "FunctionCallIdentifier")
                                               String functionCallId,

                                               @WebParam(name = "ValidityPeriod")
                                               final long validityPeriod,

                                               @WebParam(name = "Eid")
                                               final String eid,
                                               @WebParam(name = "Iccid")
                                               final String iccid,

                                               @WebParam(name = "RelatesTo", mode = WebParam.Mode.OUT, header = true,
                                                       targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                               Holder<String> relatesTo
    ) throws Exception {

        HttpServletResponse resp = WSUtils.getRespObject(context);
        final RpaEntity sender = Authenticator.getUser(context); // Get the sender
        Date startTime = Calendar.getInstance().getTime();
        String msg = "";
        final BaseResponseType.ExecutionStatus status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.ExecutedSuccess, new BaseResponseType.ExecutionStatus.StatusCode("8" +
                ".1.1", "EnableProfile", "", ""));

        Long tr = CommonImpl.enableProfile(po, sender, eid, status, iccid, RpaEntity.Type.SMDP, senderEntity,
                receiverEntity, messageId, validityPeriod, replyTo, messageType);

        if (tr == null)
            return new EnableProfileResponse(startTime, Calendar.getInstance().getTime(), status, null);
        else
            resp.sendError(Response.Status.ACCEPTED.getStatusCode(), msg);
        return null;
    }

    @WebMethod(operationName = "DisableProfile")
    @Action(input = "http://gsma.com/ES3/ProfileManagent/ES3-DisableProfile")
    public DisableProfileResponse disableProfile(@WebParam(name = "From", header = true,
            targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                                 final WsaEndPointReference senderEntity,

                                                 @WebParam(name = "To", header = true, targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                                 final String receiverEntity,
                                                 @WebParam(name = "ReplyTo", header = true, targetNamespace = "http://www.w3" +
                                                         ".org/2007/05/addressing/metadata") final
                                                 WsaEndPointReference replyTo,
                                                 @WebParam(name = "MessageID", header = true,
                                                         targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                                 final String messageId,
                                                 // WSA: Action
                                                 @WebParam(name = "Action", header = true, mode = WebParam.Mode.INOUT,
                                                         targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                                 final Holder<String> messageType,

                                                 // These are in the body
                                                 @WebParam(name = "FunctionCallIdentifier")
                                                 String functionCallId,

                                                 @WebParam(name = "ValidityPeriod")
                                                 final long validityPeriod,

                                                 @WebParam(name = "Eid")
                                                 final String eid,
                                                 @WebParam(name = "Iccid")
                                                 final String iccid,

                                                 @WebParam(name = "RelatesTo", mode = WebParam.Mode.OUT, header = true,
                                                         targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                                 Holder<String> relatesTo
    ) throws Exception {

        HttpServletResponse resp = WSUtils.getRespObject(context);
        Date startTime = Calendar.getInstance().getTime();
        final RpaEntity sender = Authenticator.getUser(context); // Get the sender

        String msg = "";
        final BaseResponseType.ExecutionStatus status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.ExecutedSuccess, new BaseResponseType.ExecutionStatus.StatusCode("8" +
                ".1.1", "", "", ""));

        Long tr = CommonImpl.disableProfile(po, sender, eid, status, iccid, RpaEntity.Type.SMDP, senderEntity,
                receiverEntity, messageId, validityPeriod, replyTo, messageType);

        if (tr == null)
            return new DisableProfileResponse(startTime, Calendar.getInstance().getTime(), status, null);
        else
            resp.sendError(Response.Status.ACCEPTED.getStatusCode(), msg);
        return null;
    }

    @WebMethod(operationName = "DeleteISDP")
    @Action(input = "http://gsma.com/ES3/ProfileManagent/ES3-DeleteISDP")
    public DeleteISDPResponse deleteISDP(@WebParam(name = "From", header = true,
            targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                         final WsaEndPointReference senderEntity,

                                         @WebParam(name = "To", header = true, targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                         final String receiverEntity,
                                         @WebParam(name = "ReplyTo", header = true, targetNamespace = "http://www.w3" +
                                                 ".org/2007/05/addressing/metadata") final
                                         WsaEndPointReference replyTo,
                                         @WebParam(name = "MessageID", header = true,
                                                 targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                         final String messageId,
                                         // WSA: Action
                                         @WebParam(name = "Action", header = true, mode = WebParam.Mode.INOUT,
                                                 targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                         final Holder<String> messageType,

                                         // These are in the body
                                         @WebParam(name = "FunctionCallIdentifier")
                                         String functionCallId,

                                         @WebParam(name = "ValidityPeriod")
                                         final long validityPeriod,

                                         @WebParam(name = "Eid")
                                         final String eid,
                                         @WebParam(name = "Iccid")
                                         final String iccid,

                                         @WebParam(name = "RelatesTo", mode = WebParam.Mode.OUT, header = true,
                                                 targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                         Holder<String> relatesTo
    ) throws Exception {

        HttpServletResponse resp = WSUtils.getRespObject(context);
        final RpaEntity sender = Authenticator.getUser(context); // Get the sender
        Date startTime = Calendar.getInstance().getTime();

        final BaseResponseType.ExecutionStatus status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.ExecutedSuccess,
                new BaseResponseType.ExecutionStatus.StatusCode("8" +
                        ".1.1", "", "", ""));

        Long tr = CommonImpl.deleteProfile(po, sender, eid, status, iccid, RpaEntity.Type.SMDP, senderEntity,
                receiverEntity, messageId, validityPeriod, replyTo, messageType);


        if (tr == null)
            return new DeleteISDPResponse(startTime, Calendar.getInstance().getTime(), status, null);
        else
            resp.sendError(Response.Status.ACCEPTED.getStatusCode(), "");

        return null;
    }

    @WebMethod(operationName = "UpdateConnectivityParameters")
    @Action(input = "http://gsma.com/ES3/ProfileManagent/ES3-UpdateConnectivityParameters")
    public UpdateConnectivityParametersResponse updateConnectivityParameters(@WebParam(name = "From", header = true,
            targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                                                             final WsaEndPointReference senderEntity,

                                                                             @WebParam(name = "To", header = true, targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                                                             final String receiverEntity,
                                                                             @WebParam(name = "ReplyTo", header = true, targetNamespace = "http://www.w3" +
                                                                                     ".org/2007/05/addressing/metadata") final
                                                                             WsaEndPointReference replyTo,
                                                                             @WebParam(name = "MessageID", header = true,
                                                                                     targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                                                             final String messageId,
                                                                             // WSA: Action
                                                                             @WebParam(name = "Action", header = true, mode = WebParam.Mode.INOUT,
                                                                                     targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                                                             final Holder<String> messageType,

                                                                             // These are in the body
                                                                             @WebParam(name = "FunctionCallIdentifier")
                                                                             String functionCallId,

                                                                             @WebParam(name = "ValidityPeriod")
                                                                             final long validityPeriod,

                                                                             @WebParam(name = "Eid")
                                                                             final String eid,
                                                                             @WebParam(name = "Iccid")
                                                                             final String iccid,
                                                                             @WebParam(name = "ConnectivityParameters")
                                                                             final String params,

                                                                             @WebParam(name = "RelatesTo", mode = WebParam.Mode.OUT, header = true,
                                                                                     targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                                                             Holder<String> relatesTo
    ) throws Exception {
        Date startTime = Calendar.getInstance().getTime();
        HttpServletResponse resp = WSUtils.getRespObject(context);


        final BaseResponseType.ExecutionStatus status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.ExecutedSuccess, new BaseResponseType.ExecutionStatus.StatusCode("8" +
                ".1.1", "", "", ""));

        RpaEntity sender = Authenticator.getUser(context);
        Long tr = CommonImpl.updateConnectivityParams(po, sender, eid, status, iccid, params, RpaEntity.Type.SMDP, senderEntity,
                receiverEntity, messageId, validityPeriod, replyTo, messageType);
        if (tr == null)
            return new UpdateConnectivityParametersResponse(startTime, Calendar.getInstance().getTime(), status, null);
        else
            resp.sendError(Response.Status.ACCEPTED.getStatusCode(), "");

        return null;
    }


    private String getSenderSMDP() {
        String name = Authenticator.getUser(context).getOid(); // Return the name
        return name;
    }


}
