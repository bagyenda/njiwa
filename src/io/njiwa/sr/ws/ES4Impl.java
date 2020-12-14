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
import io.njiwa.common.Utils;
import io.njiwa.common.model.RpaEntity;
import io.njiwa.common.ws.WSUtils;
import io.njiwa.common.ws.handlers.Authenticator;
import io.njiwa.common.ws.types.BaseResponseType;
import io.njiwa.common.ws.types.WsaEndPointReference;
import io.njiwa.sr.model.Eis;
import io.njiwa.sr.model.SmSrTransaction;
import io.njiwa.sr.transactions.EISHandoverTransaction;
import io.njiwa.sr.transactions.ReceiveEISHandoverTransaction;
import io.njiwa.sr.ws.interfaces.ES4;
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
 * Created by bagyenda on 09/05/2017.
 */
@WebService(name = "ES4", serviceName = Authenticator.SMSR_SERVICE_NAME, targetNamespace = "http://namespaces.gsma.org/esim-messaging/1")
@SOAPBinding(style = SOAPBinding.Style.RPC, use = SOAPBinding.Use.LITERAL)
@Stateless
@HandlerChain(file = "../../common/ws/handlers/ws-default-handler-chain.xml")
public class ES4Impl {

    @Inject
    PersistenceUtility po; // For saving objects
    @Resource
    private WebServiceContext context;

    @WebMethod(operationName = "GetEIS")
    @Action(input = "http://gsma.com/ES4/ProfileManagent/ES4-GetEISRequest",
            output = "http://gsma.com/ES4/ProfileManagent/ES4-GetEISResponse")
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
        messageType.value = "http://gsma.com/ES4/ProfileManagent/ES4-GetEISResponse";
        final Utils.Triple<BaseResponseType.ExecutionStatus,RpaEntity,Date> resp = CommonImpl.makeBaseResp(context,"GetEIS");
        io.njiwa.sr.ws.types.Eis eis = po.doTransaction((po, em) -> CommonImpl.getEIS(em, eid, RpaEntity.Type.MNO, resp.l, resp.k));
        return new GetEISResponse(resp.m, Calendar.getInstance().getTime(), validityPeriod,
                resp.k, eis);
    }

    @WebMethod(operationName = "PrepareSMSRChangeRequest")
    @Action(input = "http://gsma.com/ES4/eUICCManagement/ES4-PrepareSMSRChange")
    public BaseResponseType prepareSMSRChange(@WebParam(name = "From", header = true,
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
                                              @WebParam(name = "CurrentSMSRid")
                                              final String currentSMSRId) {
        Date startTime = Calendar.getInstance().getTime();
        final BaseResponseType.ExecutionStatus status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.ExecutedSuccess,
                new BaseResponseType.ExecutionStatus.StatusCode("8" +
                        ".1.1", "PrepareSMSRChange", "", ""));
        Long tr = null;
        String msg = "";
        final RpaEntity sender = Authenticator.getUser(context);
        RpaEntity smsr1 = RpaEntity.getByOID(po, currentSMSRId, RpaEntity.Type.SMSR);
        Eis.Eid xeid = null;
        try {
            xeid = new Eis.Eid(eid);
        } catch (Exception ex) {
        }

        Eis xeis = Eis.findByEid(po, eid);
        if (xeis != null)
            msg = "EIS exists";
        else if (xeid == null)
            msg = "Invalid EID format";
        else if (sender.getType() != RpaEntity.Type.MNO)
            msg = "Invalid, not a known MNO";
        else if (smsr1 == null)
            msg = "Invalid, SM-SR not known";
        else {
            // Try to make the transaction
            tr = po.doTransaction(new PersistenceUtility.Runner<Long>() {
                @Override
                public Long run(PersistenceUtility po, EntityManager em) throws Exception {
                    ReceiveEISHandoverTransaction t = new ReceiveEISHandoverTransaction(sender.getOid());
                    t.updateBaseData(senderEntity, receiverEntity, messageId, validityPeriod, replyTo, sender.getId());
                    SmSrTransaction tr = new SmSrTransaction(em, ES4.ES4_PREPARE_SMSRCHANGE, // So we can look for it
                            // below.
                            messageId, receiverEntity,
                            eid,
                            validityPeriod, true,
                            t);
                    tr.setNextSend(tr.getExpires()); // It should never go out...
                    tr.genMessageIDForTrans(em); // Make Request ID the ID.
                    em.persist(tr);
                    return tr.getId();
                }

                @Override
                public void cleanup(boolean success) {

                }
            });
        }
        // Valid EID, then check we know that SMSR. Should be enough. Right?
        if (tr == null) {
            status.status = BaseResponseType.ExecutionStatus.Status.Failed;
            status.statusCodeData.subjectCode = "1.2";
            status.statusCodeData.reasonCode = "3";
            status.statusCodeData.message = msg;
        }

        return new BaseResponseType(startTime, Calendar.getInstance().getTime(), validityPeriod, status);
    }

    @WebMethod(operationName = "SMSRChangeRequest")
    @Action(input = "http://gsma.com/ES4/eUICCManagement/ES4-SMSRChange")
    public BaseResponseType smsrChange(@WebParam(name = "From", header = true,
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
                                       @WebParam(name = "Target-Smsr-id")
                                       final String targetSMSRId) {
        Date startTime = Calendar.getInstance().getTime();
        final BaseResponseType.ExecutionStatus status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.ExecutedSuccess,
                new BaseResponseType.ExecutionStatus.StatusCode("8" +
                        ".1.1", "SMSRChange", "", ""));
        Long tr = null;
        String msg = "";
        final RpaEntity sender = Authenticator.getUser(context);
        RpaEntity smsr2 = RpaEntity.getByOID(po, targetSMSRId, RpaEntity.Type.SMSR);


        Eis xeis = Eis.findByEid(po, eid);
        if (xeis == null) {
            status.status = BaseResponseType.ExecutionStatus.Status.Failed;
            status.statusCodeData.message = "EIS exists";
            status.statusCodeData.subjectCode = "8.1.1";
            status.statusCodeData.reasonCode = "1.1";
        } else if (sender.getType() != RpaEntity.Type.MNO) {
            status.status = BaseResponseType.ExecutionStatus.Status.Failed;
            status.statusCodeData.message = "Not allowed for non-MNO";
            status.statusCodeData.subjectCode = "8.1";
            status.statusCodeData.reasonCode = "1.2";
        } else if (smsr2 == null) {
            status.status = BaseResponseType.ExecutionStatus.Status.Failed;
            status.statusCodeData.message = "SMSR-2 not known";
            status.statusCodeData.subjectCode = "8.1";
            status.statusCodeData.reasonCode = "1.2";
        } else if (!xeis.managementAllowed(sender.getOid())) {
            status.status = BaseResponseType.ExecutionStatus.Status.Failed;
            status.statusCodeData.message = "Not allowed";
            status.statusCodeData.subjectCode = "8.1";
            status.statusCodeData.reasonCode = "1.2";
        } else if (xeis.verifyPendingEuiCCHandoverTransaction(po)) {
            status.status = BaseResponseType.ExecutionStatus.Status.Failed;
            status.statusCodeData.message = "Another handover pending";
            status.statusCodeData.subjectCode = "8.1";
            status.statusCodeData.reasonCode = "1.2";
        } else {
            // Try to make the transaction
            tr = po.doTransaction(new PersistenceUtility.Runner<Long>() {
                @Override
                public Long run(PersistenceUtility po, EntityManager em) throws Exception {
                    EISHandoverTransaction t = new EISHandoverTransaction(sender.getOid(), smsr2.getId(), xeis.getId());
                    t.updateBaseData(senderEntity, receiverEntity, messageId, validityPeriod, replyTo, sender.getId());
                    SmSrTransaction tr = new SmSrTransaction(em, ES4.ES4_SMSRCHANGE,
                            messageId, receiverEntity,
                            eid,
                            validityPeriod, true,
                            t);
                    tr.genMessageIDForTrans(em); // Make Request ID the ID.
                    em.persist(tr);
                    xeis.setPendingEuiccHandoverTransaction(tr.getId()); // Record it
                    return tr.getId();
                }

                @Override
                public void cleanup(boolean success) {

                }
            });
        }
        // Valid EID, then check we know that SMSR. Should be enough. Right?
        if (tr == null) {
            status.status = BaseResponseType.ExecutionStatus.Status.Failed;
            status.statusCodeData.subjectCode = "1.2";
            status.statusCodeData.reasonCode = "3";
            status.statusCodeData.message = msg;
        }

        return new BaseResponseType(startTime, Calendar.getInstance().getTime(), validityPeriod, status);
    }

    @WebMethod(operationName = "DeleteProfile")
    @Action(input = "http://gsma.com/ES4/ProfileManagent/ES4-DeleteProfile")
    public BaseResponseType deleteISDP(@WebParam(name = "From", header = true,
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

        Long tr = po.doTransaction((po, em) -> CommonImpl.deleteProfile(em, sender, eid, status, iccid, senderEntity,
                receiverEntity, messageId, validityPeriod, replyTo, messageType));


        if (tr == null)
            return new BaseResponseType(startTime, Calendar.getInstance().getTime(), validityPeriod, status);
        else
            resp.sendError(Response.Status.ACCEPTED.getStatusCode(), "");

        return null;
    }


    @WebMethod(operationName = "DisableProfile")
    @Action(input = "http://gsma.com/ES4/ProfileManagent/ES4-DisableProfile")
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

        Long tr = po.doTransaction((po, em) -> CommonImpl.disableProfile(em, sender, eid, status, iccid,  senderEntity,
                receiverEntity, messageId, validityPeriod, replyTo, messageType));

        if (tr == null)
            return new DisableProfileResponse(startTime, Calendar.getInstance().getTime(), status, null);
        else
            resp.sendError(Response.Status.ACCEPTED.getStatusCode(), msg);
        return null;
    }

    @WebMethod(operationName = "EnableProfile")
    @Action(input = "http://gsma.com/ES4/ProfileManagent/ES4-EnableProfile")
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

        Long tr = po.doTransaction((po, em) -> CommonImpl.enableProfile(em, sender, eid, status, iccid,  senderEntity,
                receiverEntity, messageId, validityPeriod, replyTo, messageType));

        if (tr == null)
            return new EnableProfileResponse(startTime, Calendar.getInstance().getTime(), status, null);
        else
            resp.sendError(Response.Status.ACCEPTED.getStatusCode(), msg);
        return null;
    }


    @WebMethod(operationName = "UpdatePolicyRules")
    @Action(input = "http://gsma.com/ES4/ProfileManagent/ES4-UpdatePolicyRules")
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
        return po.doTransaction((po, em) -> CommonImpl.updatePolicyRules(em, sender, eid, iccid, pol2));
    }

    @WebMethod(operationName = "AuditEIS")
    @Action(input = "http://gsma.com/ES4/ProfileManagent/ES4-AuditEIS",
            output = "http://gsma.com/ES4/ProfileManagentCallback/ES4-AuditEIS")
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
                                    @WebParam(name="Iccid")
                              final List<String> iccids,
                                    @WebParam(name = "RelatesTo", mode = WebParam.Mode.OUT, header = true,
                                      targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                              Holder<String> relatesTo
    ) throws  Exception {
        Date startDate = Calendar.getInstance().getTime();
        HttpServletResponse resp = WSUtils.getRespObject(context);
        final RpaEntity sender = Authenticator.getUser(context); // Get the sender

        final BaseResponseType.ExecutionStatus status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.ExecutedSuccess, new BaseResponseType.ExecutionStatus.StatusCode("8" +
                ".1.1", "EnableProfile", "", ""));
        Long tr = po.doTransaction((po, em) -> CommonImpl.auditEIS(em,sender,eid,null,status, RpaEntity.Type.MNO,senderEntity,receiverEntity,
                messageId,validityPeriod,replyTo,messageType));
        if (tr == null)
            return new AuditEISResponse(startDate,Calendar.getInstance().getTime(),validityPeriod,status,null);
        resp.sendError(Response.Status.ACCEPTED.getStatusCode(), "");
        return null;
    }
}
