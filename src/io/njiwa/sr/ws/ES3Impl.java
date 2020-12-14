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
import io.njiwa.sr.model.ProfileInfo;
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

/**
 * Created by bagyenda on 08/06/2016.
 */


// Sending of 202 response for Accept, according to:
// http://stackoverflow.com/questions/19297722/how-to-make-jax-ws-webservice-respond-with-specific-http-code
@WebService(name = "ES3", serviceName = Authenticator.SMSR_SERVICE_NAME, targetNamespace = "http://namespaces.gsma" +
        ".org/esim-messaging/1")
@SOAPBinding(style = SOAPBinding.Style.RPC, use = SOAPBinding.Use.LITERAL)
@Stateless
@HandlerChain(file = "../../common/ws/handlers/ws-default-handler-chain.xml")
public class ES3Impl {

    @Inject
    PersistenceUtility po; // For saving objects
    @Resource
    private WebServiceContext context;


    @WebMethod(operationName = "GetEIS")
    @Action(input = "http://gsma.com/ES3/ProfileManagent/ES3-GetEISRequest", output = "http://gsma" +
            ".com/ES3/ProfileManagent/ES3-GetEISResponse")
    @WebResult(name = "FunctionExecutionStatus")
    public GetEISResponse getEIS(@WebParam(name = "From", header = true, targetNamespace = "http://www.w3" +
            ".org/2007/05/addressing/metadata") WsaEndPointReference senderEntity,

                                 @WebParam(name = "To", header = true, targetNamespace = "http://www.w3" +
                                         ".org/2007/05/addressing/metadata") String receiverEntity, @WebParam(name =
            "ReplyTo", header = true, targetNamespace = "http://www.w3" + ".org/2007/05/addressing/metadata") WsaEndPointReference replyTo, @WebParam(name = "MessageID", header = true, targetNamespace = "http://www.w3.org/2007/05/addressing/metadata") String messageId,
                                 // WSA: Action
                                 @WebParam(name = "Action", header = true, mode = WebParam.Mode.INOUT,
                                         targetNamespace = "http://www.w3.org/2007/05/addressing/metadata") Holder<String> messageType,

                                 // These are in the body
                                 @WebParam(name = "FunctionCallIdentifier") String functionCallId,

                                 @WebParam(name = "ValidityPeriod") long validityPeriod,

                                 @WebParam(name = "Eid") final String eid, @WebParam(name = "RelatesTo", mode =
            WebParam.Mode.OUT, header = true, targetNamespace = "http://www.w3.org/2007/05/addressing/metadata") Holder<String> relatesTo) {
        relatesTo.value = messageId;
        messageType.value = "http://gsma.com/ES3/ProfileManagent/ES3-GetEISResponse";
        final Utils.Triple<BaseResponseType.ExecutionStatus, RpaEntity, Date> resp = CommonImpl.makeBaseResp(context,
                "GetEIS");
        io.njiwa.sr.ws.types.Eis eis = po.doTransaction((po, em) -> CommonImpl.getEIS(em, eid, RpaEntity.Type.SMDP,
                resp.l, resp.k));
        return new GetEISResponse(resp.m, Calendar.getInstance().getTime(), validityPeriod, resp.k, eis);
    }

    @WebMethod(operationName = "AuditEIS")
    @Action(input = "http://gsma.com/ES3/ProfileManagent/ES3-AuditEIS", output = "http://gsma" +
            ".com/ES3/ProfileManagentCallback/ES3-AuditEIS")
    @WebResult(name = "FunctionExecutionStatus")
    public AuditEISResponse auditEIS(@WebParam(name = "From", header = true, targetNamespace = "http://www.w3" +
            ".org/2007/05/addressing/metadata") WsaEndPointReference senderEntity,

                                     @WebParam(name = "To", header = true, targetNamespace = "http://www.w3" +
                                             ".org/2007/05/addressing/metadata") String receiverEntity,
                                     @WebParam(name = "ReplyTo", header = true, targetNamespace = "http://www.w3" +
                                             ".org/2007/05/addressing/metadata") WsaEndPointReference replyTo,
                                     @WebParam(name = "MessageID", header = true, targetNamespace = "http://www.w3" +
                                             ".org/2007/05/addressing/metadata") String messageId,
                                     // WSA: Action
                                     @WebParam(name = "Action", header = true, mode = WebParam.Mode.INOUT,
                                             targetNamespace = "http://www.w3.org/2007/05/addressing/metadata") Holder<String> messageType,

                                     // These are in the body
                                     @WebParam(name = "FunctionCallIdentifier") String functionCallId,

                                     @WebParam(name = "ValidityPeriod") long validityPeriod,

                                     @WebParam(name = "Eid") final String eid, @WebParam(name = "RelatesTo", mode =
            WebParam.Mode.OUT, header = true, targetNamespace = "http://www.w3.org/2007/05/addressing/metadata") Holder<String> relatesTo) throws Exception {

        Date startDate = Calendar.getInstance().getTime();
        HttpServletResponse resp = WSUtils.getRespObject(context);
        final RpaEntity sender = Authenticator.getUser(context); // Get the sender

        final BaseResponseType.ExecutionStatus status =
                new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.ExecutedSuccess,
                        new BaseResponseType.ExecutionStatus.StatusCode("8" + ".1.1", "AuditEIS", "", ""));
        Long tr = po.doTransaction((po, em) -> CommonImpl.auditEIS(em, sender, eid, null, status, RpaEntity.Type.SMDP
                , senderEntity, receiverEntity, messageId, validityPeriod, replyTo, messageType));
        if (tr == null)
            return new AuditEISResponse(startDate, Calendar.getInstance().getTime(), validityPeriod, status, null);
        resp.sendError(Response.Status.ACCEPTED.getStatusCode(), "");
        return new AuditEISResponse(startDate, Calendar.getInstance().getTime(), validityPeriod, status, null);
    }

    @WebMethod(operationName = "SendData")
    @Action(input = "http://gsma.com/ES3/ProfileManagent/ES3-SendData")
    public SendDataResponse sendData(@WebParam(name = "From", header = true, targetNamespace = "http://www.w3" +
            ".org/2007/05/addressing/metadata") WsaEndPointReference senderEntity,

                                     @WebParam(name = "To", header = true, targetNamespace = "http://www.w3" +
                                             ".org/2007/05/addressing/metadata") final String receiverEntity,
                                     @WebParam(name = "ReplyTo", header = true, targetNamespace = "http://www.w3" +
                                             ".org/2007/05/addressing/metadata") WsaEndPointReference replyTo,
                                     @WebParam(name = "MessageID", header = true, targetNamespace = "http://www.w3" +
                                             ".org/2007/05/addressing/metadata") final String messageId,
                                     // WSA: Action
                                     @WebParam(name = "Action", header = true, mode = WebParam.Mode.INOUT,
                                             targetNamespace = "http://www.w3.org/2007/05/addressing/metadata") final Holder<String> messageType,

                                     // These are in the body
                                     @WebParam(name = "FunctionCallIdentifier") String functionCallId,

                                     @WebParam(name = "ValidityPeriod") final long validityPeriod,

                                     @WebParam(name = "Eid") final String eid,
                                     @WebParam(name = "sd-aid") final String aid,
                                     @WebParam(name = "Data") final String data,

                                     @WebParam(name = "moreToDo") final boolean more, @WebParam(name = "RelatesTo",
            mode = WebParam.Mode.OUT, header = true, targetNamespace = "http://www.w3.org/2007/05/addressing/metadata"
    ) Holder<String> relatesTo) throws Exception {
        // Send 202 response for Accept, according to:
        // http://stackoverflow.com/questions/19297722/how-to-make-jax-ws-webservice-respond-with-specific-http-code
        HttpServletResponse resp = WSUtils.getRespObject(context);

        Date startTime = Calendar.getInstance().getTime();
        final BaseResponseType.ExecutionStatus status =
                new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.ExecutedSuccess,
                        new BaseResponseType.ExecutionStatus.StatusCode("8" + ".1.1", "SendData", "", ""));
        final RpaEntity sender = Authenticator.getUser(context);
        Long tr = po.doTransaction((po, em) -> CommonImpl.sendData(em, senderEntity, replyTo, eid, messageType.value,
                aid, data, more, messageId, validityPeriod, receiverEntity, sender, status));

        String msg = tr == null ? "" : "Error";

        if (tr == null)  // WE had an error, send response
            return new SendDataResponse(startTime, Calendar.getInstance().getTime(), validityPeriod, status, null);
        else resp.sendError(Response.Status.ACCEPTED.getStatusCode(), msg);
        return null; // Because we have sent an HTTP response
    }

    @WebMethod(operationName = "ProfileDownloadCompleted")
    @Action(input = "http://gsma.com/ES3/ProfileManagent/ES3-ProfileDownloadCompleted")
    public BaseResponseType profileDownloadCompleted(@WebParam(name = "From", header = true, targetNamespace = "http" +
            "://www.w3.org/2007/05/addressing/metadata") WsaEndPointReference senderEntity,

                                                     @WebParam(name = "To", header = true, targetNamespace = "http" +
                                                             "://www.w3.org/2007/05/addressing/metadata") final String receiverEntity, @WebParam(name = "ReplyTo", header = true, targetNamespace = "http://www.w3" + ".org/2007/05/addressing/metadata") WsaEndPointReference replyTo, @WebParam(name = "MessageID", header = true, targetNamespace = "http://www.w3.org/2007/05/addressing/metadata") final String messageId,
                                                     // WSA: Action
                                                     @WebParam(name = "Action", header = true, mode =
                                                             WebParam.Mode.INOUT, targetNamespace = "http://www.w3" +
                                                             ".org/2007/05/addressing/metadata") final Holder<String> messageType,

                                                     // These are in the body
                                                     @WebParam(name = "FunctionCallIdentifier") String functionCallId,

                                                     @WebParam(name = "ValidityPeriod") final long validityPeriod,

                                                     @WebParam(name = "Eid") final String eid, @WebParam(name =
            "Iccid") final String iccid, @WebParam(name = "ProfileType") final String profileType, @WebParam(name =
            "SubscriptionAddress") final SubscriptionAddress subscriptionAddress,
                                                     @WebParam(name = "pol2") final Pol2Type pol2) {
        Date startDate = Calendar.getInstance().getTime();

        final BaseResponseType.ExecutionStatus.StatusCode code = new BaseResponseType.ExecutionStatus.StatusCode();
        code.subjectCode = "8.1.1";
        code.reasonCode = "";
        code.message = "";
        code.subjectIdentifier = "";
        BaseResponseType.ExecutionStatus status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.ExecutedSuccess, code);
        boolean t = po.doTransaction((po, em) -> CommonImpl.profileDownloadComplete(em,status,Authenticator.getUser(context),
                eid,iccid,profileType,subscriptionAddress,pol2));

        if (!t)
            status.status = BaseResponseType.ExecutionStatus.Status.Failed;

        Date endDate = Calendar.getInstance().getTime();

        BaseResponseType resp = new BaseResponseType(startDate, endDate, validityPeriod, status);
        return resp;
    }

    @WebMethod(operationName = "UpdatePolicyRules")
    @Action(input = "http://gsma.com/ES3/ProfileManagent/ES3-UpdatePolicyRules")
    public BaseResponseType updatePolicyRules(@WebParam(name = "From", header = true, targetNamespace = "http://www" +
            ".w3.org/2007/05/addressing/metadata") WsaEndPointReference senderEntity,

                                              @WebParam(name = "To", header = true, targetNamespace = "http://www.w3" +
                                                      ".org/2007/05/addressing/metadata") final String receiverEntity
            , @WebParam(name = "ReplyTo", header = true, targetNamespace = "http://www.w3" + ".org/2007/05/addressing" +
            "/metadata") WsaEndPointReference replyTo, @WebParam(name = "MessageID", header = true, targetNamespace =
            "http://www.w3.org/2007/05/addressing/metadata") final String messageId,
                                              // WSA: Action
                                              @WebParam(name = "Action", header = true, mode = WebParam.Mode.INOUT,
                                                      targetNamespace = "http://www.w3.org/2007/05/addressing" +
                                                              "/metadata") final Holder<String> messageType,

                                              // These are in the body
                                              @WebParam(name = "FunctionCallIdentifier") String functionCallId,

                                              @WebParam(name = "ValidityPeriod") final long validityPeriod,

                                              @WebParam(name = "Eid") final String eid,
                                              @WebParam(name = "Iccid") final String iccid,
                                              @WebParam(name = "pol2") final Pol2Type pol2) {
        final RpaEntity sender = Authenticator.getUser(context); // Get the sender
        return po.doTransaction((po, em) -> CommonImpl.updatePolicyRules(em, sender, eid, iccid, pol2));
    }

    @WebMethod(operationName = "CreateISDP")
    @Action(input = "http://gsma.com/ES3/ProfileManagent/ES3-CreateISDP")
    public CreateISDPResponse createISDP(@WebParam(name = "From", header = true, targetNamespace = "http://www.w3" +
            ".org/2007/05/addressing/metadata") final WsaEndPointReference senderEntity,

                                         @WebParam(name = "To", header = true, targetNamespace = "http://www.w3" +
                                                 ".org/2007/05/addressing/metadata") final String receiverEntity,
                                         @WebParam(name = "ReplyTo", header = true, targetNamespace =
                                                 "http://www.w3" + ".org/2007/05/addressing/metadata") final WsaEndPointReference replyTo, @WebParam(name = "MessageID", header = true, targetNamespace = "http://www.w3.org/2007/05/addressing/metadata") final String messageId,
                                         // WSA: Action
                                         @WebParam(name = "Action", header = true, mode = WebParam.Mode.INOUT,
                                                 targetNamespace = "http://www.w3.org/2007/05/addressing/metadata") final Holder<String> messageType,

                                         // These are in the body
                                         @WebParam(name = "FunctionCallIdentifier") String functionCallId,

                                         @WebParam(name = "ValidityPeriod") final long validityPeriod,

                                         @WebParam(name = "Eid") final String eid,
                                         @WebParam(name = "Iccid") final String iccid,
                                         @WebParam(name = "Mno-id") final String mnoId,

                                         @WebParam(name = "RequiredMemory") final int requiredMem,

                                         @WebParam(name = "moreToDo") final boolean more, @WebParam(name = "RelatesTo"
            , mode = WebParam.Mode.OUT, header = true, targetNamespace = "http://www.w3.org/2007/05/addressing" +
            "/metadata") Holder<String> relatesTo) throws Exception {

        // Send 202 response for Accept, according to:
        // http://stackoverflow.com/questions/19297722/how-to-make-jax-ws-webservice-respond-with-specific-http-code
        HttpServletResponse resp = WSUtils.getRespObject(context);

        String msg = "";
        final BaseResponseType.ExecutionStatus status =
                new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.ExecutedSuccess,
                        new BaseResponseType.ExecutionStatus.StatusCode("8" + ".1.1", "CreateISDP", "", ""));
        Date startTime = Calendar.getInstance().getTime();
        Long tr = po.doTransaction((po1, em) -> CommonImpl.createISDP(em, eid, status, iccid, mnoId, senderEntity,
                receiverEntity, messageId, validityPeriod, replyTo, messageType, requiredMem, more,
                Authenticator.getUser(context)));


        if (tr == null)  // WE had an error, do the async call back immediately
            return new CreateISDPResponse(startTime, Calendar.getInstance().getTime(), validityPeriod, status, null,
                    null);
        else resp.sendError(Response.Status.ACCEPTED.getStatusCode(), msg);
        return null;
    }

    @WebMethod(operationName = "EnableProfile")
    @Action(input = "http://gsma.com/ES3/ProfileManagent/ES3-EnableProfile")
    public EnableProfileResponse enableProfile(@WebParam(name = "From", header = true, targetNamespace = "http://www" +
            ".w3.org/2007/05/addressing/metadata") final WsaEndPointReference senderEntity,

                                               @WebParam(name = "To", header = true, targetNamespace = "http://www.w3" +
                                                       ".org/2007/05/addressing/metadata") final String receiverEntity, @WebParam(name = "ReplyTo", header = true, targetNamespace = "http://www.w3" + ".org/2007/05/addressing/metadata") final WsaEndPointReference replyTo, @WebParam(name = "MessageID", header = true, targetNamespace = "http://www.w3.org/2007/05/addressing/metadata") final String messageId,
                                               // WSA: Action
                                               @WebParam(name = "Action", header = true, mode = WebParam.Mode.INOUT,
                                                       targetNamespace = "http://www.w3.org/2007/05/addressing" +
                                                               "/metadata") final Holder<String> messageType,

                                               // These are in the body
                                               @WebParam(name = "FunctionCallIdentifier") String functionCallId,

                                               @WebParam(name = "ValidityPeriod") final long validityPeriod,

                                               @WebParam(name = "Eid") final String eid,
                                               @WebParam(name = "Iccid") final String iccid,

                                               @WebParam(name = "RelatesTo", mode = WebParam.Mode.OUT, header = true,
                                                       targetNamespace = "http://www.w3.org/2007/05/addressing" +
                                                               "/metadata") Holder<String> relatesTo) throws Exception {

        HttpServletResponse resp = WSUtils.getRespObject(context);
        final RpaEntity sender = Authenticator.getUser(context); // Get the sender
        Date startTime = Calendar.getInstance().getTime();
        String msg = "";
        final BaseResponseType.ExecutionStatus status =
                new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.ExecutedSuccess,
                        new BaseResponseType.ExecutionStatus.StatusCode("8" + ".1.1", "EnableProfile", "", ""));

        Long tr = po.doTransaction((po, em) -> CommonImpl.enableProfile(em, sender, eid, status, iccid, senderEntity,
                receiverEntity, messageId, validityPeriod, replyTo, messageType));

        if (tr == null) return new EnableProfileResponse(startTime, Calendar.getInstance().getTime(), status, null);
        else resp.sendError(Response.Status.ACCEPTED.getStatusCode(), msg);
        return null;
    }

    @WebMethod(operationName = "DisableProfile")
    @Action(input = "http://gsma.com/ES3/ProfileManagent/ES3-DisableProfile")
    public DisableProfileResponse disableProfile(@WebParam(name = "From", header = true, targetNamespace = "http" +
            "://www.w3.org/2007/05/addressing/metadata") final WsaEndPointReference senderEntity,

                                                 @WebParam(name = "To", header = true, targetNamespace = "http://www" +
                                                         ".w3.org/2007/05/addressing/metadata") final String receiverEntity, @WebParam(name = "ReplyTo", header = true, targetNamespace = "http://www.w3" + ".org/2007/05/addressing/metadata") final WsaEndPointReference replyTo, @WebParam(name = "MessageID", header = true, targetNamespace = "http://www.w3.org/2007/05/addressing/metadata") final String messageId,
                                                 // WSA: Action
                                                 @WebParam(name = "Action", header = true, mode = WebParam.Mode.INOUT
                                                         , targetNamespace = "http://www.w3.org/2007/05/addressing" +
                                                         "/metadata") final Holder<String> messageType,

                                                 // These are in the body
                                                 @WebParam(name = "FunctionCallIdentifier") String functionCallId,

                                                 @WebParam(name = "ValidityPeriod") final long validityPeriod,

                                                 @WebParam(name = "Eid") final String eid,
                                                 @WebParam(name = "Iccid") final String iccid,

                                                 @WebParam(name = "RelatesTo", mode = WebParam.Mode.OUT, header =
                                                         true, targetNamespace = "http://www.w3" +
                                                         ".org/2007/05/addressing/metadata") Holder<String> relatesTo) throws Exception {

        HttpServletResponse resp = WSUtils.getRespObject(context);
        Date startTime = Calendar.getInstance().getTime();
        final RpaEntity sender = Authenticator.getUser(context); // Get the sender

        String msg = "";
        final BaseResponseType.ExecutionStatus status =
                new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.ExecutedSuccess,
                        new BaseResponseType.ExecutionStatus.StatusCode("8" + ".1.1", "", "", ""));

        Long tr = po.doTransaction((po, em) -> CommonImpl.disableProfile(em, sender, eid, status, iccid, senderEntity
                , receiverEntity, messageId, validityPeriod, replyTo, messageType));

        if (tr == null) return new DisableProfileResponse(startTime, Calendar.getInstance().getTime(), status, null);
        else resp.sendError(Response.Status.ACCEPTED.getStatusCode(), msg);
        return null;
    }

    @WebMethod(operationName = "DeleteISDP")
    @Action(input = "http://gsma.com/ES3/ProfileManagent/ES3-DeleteISDP")
    public DeleteISDPResponse deleteISDP(@WebParam(name = "From", header = true, targetNamespace = "http://www.w3" +
            ".org/2007/05/addressing/metadata") final WsaEndPointReference senderEntity,

                                         @WebParam(name = "To", header = true, targetNamespace = "http://www.w3" +
                                                 ".org/2007/05/addressing/metadata") final String receiverEntity,
                                         @WebParam(name = "ReplyTo", header = true, targetNamespace =
                                                 "http://www.w3" + ".org/2007/05/addressing/metadata") final WsaEndPointReference replyTo, @WebParam(name = "MessageID", header = true, targetNamespace = "http://www.w3.org/2007/05/addressing/metadata") final String messageId,
                                         // WSA: Action
                                         @WebParam(name = "Action", header = true, mode = WebParam.Mode.INOUT,
                                                 targetNamespace = "http://www.w3.org/2007/05/addressing/metadata") final Holder<String> messageType,

                                         // These are in the body
                                         @WebParam(name = "FunctionCallIdentifier") String functionCallId,

                                         @WebParam(name = "ValidityPeriod") final long validityPeriod,

                                         @WebParam(name = "Eid") final String eid,
                                         @WebParam(name = "Iccid") final String iccid,

                                         @WebParam(name = "RelatesTo", mode = WebParam.Mode.OUT, header = true,
                                                 targetNamespace = "http://www.w3.org/2007/05/addressing/metadata") Holder<String> relatesTo) throws Exception {

        HttpServletResponse resp = WSUtils.getRespObject(context);
        final RpaEntity sender = Authenticator.getUser(context); // Get the sender
        Date startTime = Calendar.getInstance().getTime();

        final BaseResponseType.ExecutionStatus status =
                new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.ExecutedSuccess,
                        new BaseResponseType.ExecutionStatus.StatusCode("8" + ".1.1", "", "", ""));

        Long tr = po.doTransaction((po, em) -> CommonImpl.deleteProfile(em, sender, eid, status, iccid, senderEntity,
                receiverEntity, messageId, validityPeriod, replyTo, messageType));


        if (tr == null) return new DeleteISDPResponse(startTime, Calendar.getInstance().getTime(), status, null);
        else resp.sendError(Response.Status.ACCEPTED.getStatusCode(), "");

        return null;
    }

    @WebMethod(operationName = "UpdateConnectivityParameters")
    @Action(input = "http://gsma.com/ES3/ProfileManagent/ES3-UpdateConnectivityParameters")
    public UpdateConnectivityParametersResponse updateConnectivityParameters(@WebParam(name = "From", header = true,
            targetNamespace = "http://www.w3.org/2007/05/addressing/metadata") final WsaEndPointReference senderEntity,

                                                                             @WebParam(name = "To", header = true,
                                                                                     targetNamespace = "http://www.w3" +
                                                                                             ".org/2007/05/addressing" +
                                                                                             "/metadata") final String receiverEntity, @WebParam(name = "ReplyTo", header = true, targetNamespace = "http://www.w3" + ".org/2007/05/addressing/metadata") final WsaEndPointReference replyTo, @WebParam(name = "MessageID", header = true, targetNamespace = "http://www.w3.org/2007/05/addressing/metadata") final String messageId,
                                                                             // WSA: Action
                                                                             @WebParam(name = "Action", header = true
                                                                                     , mode = WebParam.Mode.INOUT,
                                                                                     targetNamespace = "http://www.w3" +
                                                                                             ".org/2007/05/addressing" +
                                                                                             "/metadata") final Holder<String> messageType,

                                                                             // These are in the body
                                                                             @WebParam(name = "FunctionCallIdentifier"
                                                                             ) String functionCallId,

                                                                             @WebParam(name = "ValidityPeriod") final long validityPeriod,

                                                                             @WebParam(name = "Eid") final String eid
            , @WebParam(name = "Iccid") final String iccid, @WebParam(name = "ConnectivityParameters") final String params,

                                                                             @WebParam(name = "RelatesTo", mode =
                                                                                     WebParam.Mode.OUT, header = true
                                                                                     , targetNamespace = "http://www" +
                                                                                     ".w3.org/2007/05/addressing" +
                                                                                     "/metadata") Holder<String> relatesTo) throws Exception {
        Date startTime = Calendar.getInstance().getTime();
        HttpServletResponse resp = WSUtils.getRespObject(context);


        final BaseResponseType.ExecutionStatus status =
                new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.ExecutedSuccess,
                        new BaseResponseType.ExecutionStatus.StatusCode("8" + ".1.1", "", "", ""));

        RpaEntity sender = Authenticator.getUser(context);
        Long tr = po.doTransaction((po, em) -> CommonImpl.updateConnectivityParams(em, sender, eid, status, iccid,
                params, RpaEntity.Type.SMDP, senderEntity, receiverEntity, messageId, validityPeriod, replyTo,
                messageType));
        if (tr == null)
            return new UpdateConnectivityParametersResponse(startTime, Calendar.getInstance().getTime(), status, null);
        else resp.sendError(Response.Status.ACCEPTED.getStatusCode(), "");

        return null;
    }


    private String getSenderSMDP() {
        String name = Authenticator.getUser(context).getOid(); // Return the name
        return name;
    }


}
