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

package io.njiwa.dp.ws;

import io.njiwa.common.PersistenceUtility;
import io.njiwa.common.ws.WSUtils;
import io.njiwa.common.ws.handlers.Authenticator;
import io.njiwa.common.ws.types.WsaEndPointReference;
import io.njiwa.common.ws.types.BaseResponseType;
import io.njiwa.dp.transactions.ChangeProfileStatusTransaction;

import javax.annotation.Resource;
import javax.ejb.Stateless;
import javax.enterprise.concurrent.ManagedExecutorService;
import javax.inject.Inject;
import javax.jws.HandlerChain;
import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebService;
import javax.jws.soap.SOAPBinding;
import javax.ws.rs.core.Response;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.ws.Action;
import javax.xml.ws.Holder;
import javax.xml.ws.WebServiceContext;

/**
 * Created by bagyenda on 06/04/2017.
 */
@WebService(name = "ES3", serviceName = Authenticator.SMDP_SERVICE_NAME,targetNamespace = "http://namespaces.gsma.org/esim-messaging/1")
@SOAPBinding(style = SOAPBinding.Style.RPC, use = SOAPBinding.Use.LITERAL)
@Stateless
@HandlerChain(file = "../../common/ws/handlers/ws-default-handler-chain.xml")
public class ES3ResponseImpl {
    @Inject
    PersistenceUtility po; // For saving objects
    @Resource
    private ManagedExecutorService runner; //!< For use by async callbacks
    @Resource
    private WebServiceContext context;

    @WebMethod(operationName = "CreateISDPResponse")
    @Action(input = "http://gsma.com/ES3/ProfileManagentCallBack/ES3-CreateISDP")
    public String createISDPResponse(@WebParam(name = "From", header = true, targetNamespace = "http://www.w3" +
            ".org/2007/05/addressing/metadata")
                                             WsaEndPointReference senderEntity,

                                     @WebParam(name = "To", header = true, targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                     final String receiverEntity,

                                     @WebParam(name = "relatesTo", header = true,
                                             targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                     final String messageId,
                                     // WSA: Action
                                     @WebParam(name = "Action", header = true, mode = WebParam.Mode.INOUT,
                                             targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                     final Holder<String> messageType,
                                     @WebParam(name = "ProcessingStart", targetNamespace = "http://namespaces.gsma" +
                                             ".org/esim-messaging/1")
                                     XMLGregorianCalendar processingStart,
                                     @WebParam(name = "ProcessingEnd")
                                     XMLGregorianCalendar processingEnd,
                                     @WebParam(name = "AcceptableValidityPeriod", targetNamespace = "http://namespaces.gsma" +
                                             ".org/esim-messaging/1")
                                     long acceptablevalidity,
                                     @WebParam(name = "FunctionExecutionStatus", targetNamespace = "http://namespaces.gsma" +
                                             ".org/esim-messaging/1")
                                     BaseResponseType.ExecutionStatus executionStatus,

                                     @WebParam(name = "Isd-p-aid", targetNamespace = "http://namespaces.gsma" +
                                             ".org/esim-messaging/1")
                                     String aid,
                                     @WebParam(name = "EuiccResponseData", targetNamespace = "http://namespaces.gsma" +
                                             ".org/esim-messaging/1")
                                     String data

    ) throws Exception {
        po.doTransaction((po1,em) ->  {CommonImpl.createISDPResponseHandler(em,aid,messageId,data); return true;});

        WSUtils.getRespObject(context).sendError(Response.Status.ACCEPTED.getStatusCode(), "");

        return "";
    }

    @WebMethod(operationName = "SendDataResponse")
    @Action(input = "http://gsma.com/ES3/ProfileManagentCallBack/ES3-SendData")
    public String sendDataResponse(@WebParam(name = "From", header = true, targetNamespace = "http://www.w3" +
            ".org/2007/05/addressing/metadata")
                                     WsaEndPointReference senderEntity,

                                     @WebParam(name = "To", header = true, targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                     final String receiverEntity,

                                     @WebParam(name = "relatesTo", header = true,
                                             targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                     final String messageId,
                                     // WSA: Action
                                     @WebParam(name = "Action", header = true, mode = WebParam.Mode.INOUT,
                                             targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                     final Holder<String> messageType,
                                     @WebParam(name = "ProcessingStart", targetNamespace = "http://namespaces.gsma" +
                                             ".org/esim-messaging/1")
                                     XMLGregorianCalendar processingStart,
                                     @WebParam(name = "ProcessingEnd")
                                     XMLGregorianCalendar processingEnd,
                                     @WebParam(name = "AcceptableValidityPeriod", targetNamespace = "http://namespaces.gsma" +
                                             ".org/esim-messaging/1")
                                     long acceptablevalidity,
                                     @WebParam(name = "FunctionExecutionStatus", targetNamespace = "http://namespaces.gsma" +
                                             ".org/esim-messaging/1")
                                     BaseResponseType.ExecutionStatus executionStatus,
                                     @WebParam(name = "EuiccResponseData", targetNamespace = "http://namespaces.gsma" +
                                             ".org/esim-messaging/1")
                                     String data

    ) throws Exception {

      po.doTransaction((po1,em) ->  { CommonImpl.sendDataResponseHandler(em,executionStatus,messageId,data); return true;});

        WSUtils.getRespObject(context).sendError(Response.Status.ACCEPTED.getStatusCode(), "");
        return "";
    }

    @WebMethod(operationName = "EnableISDPResponse")
    @Action(input = "http://gsma.com/ES3/ProfileManagentCallBack/ES3-EnableISDP")
    public String enableISDPResponse(@WebParam(name = "From", header = true, targetNamespace = "http://www.w3" +
            ".org/2007/05/addressing/metadata")
                                     WsaEndPointReference senderEntity,

                                     @WebParam(name = "To", header = true, targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                     final String receiverEntity,

                                     @WebParam(name = "relatesTo", header = true,
                                             targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                     final String messageId,
                                     // WSA: Action
                                     @WebParam(name = "Action", header = true, mode = WebParam.Mode.INOUT,
                                             targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                     final Holder<String> messageType,
                                     @WebParam(name = "ProcessingStart", targetNamespace = "http://namespaces.gsma" +
                                             ".org/esim-messaging/1")
                                     XMLGregorianCalendar processingStart,
                                     @WebParam(name = "ProcessingEnd")
                                     XMLGregorianCalendar processingEnd,
                                     @WebParam(name = "AcceptableValidityPeriod", targetNamespace = "http://namespaces.gsma" +
                                             ".org/esim-messaging/1")
                                     long acceptablevalidity,
                                     @WebParam(name = "FunctionExecutionStatus", targetNamespace = "http://namespaces.gsma" +
                                             ".org/esim-messaging/1")
                                     BaseResponseType.ExecutionStatus executionStatus,

                                     @WebParam(name = "EuiccResponseData", targetNamespace = "http://namespaces.gsma" +
                                             ".org/esim-messaging/1")
                                     String data

    ) throws Exception {

        po.doTransaction((p1,em) -> {CommonImpl.ISDPstatusChangeresponseHandler(em,messageId, ChangeProfileStatusTransaction.Action.ENABLE, executionStatus,data); return true;});

        WSUtils.getRespObject(context).sendError(Response.Status.ACCEPTED.getStatusCode(), "");

        return "";
    }

    @WebMethod(operationName = "DeleteISDPResponse")
    @Action(input = "http://gsma.com/ES3/ProfileManagentCallBack/ES3-DeleteISDP")
    public String deleteISDPResponse(@WebParam(name = "From", header = true, targetNamespace = "http://www.w3" +
            ".org/2007/05/addressing/metadata")
                                      WsaEndPointReference senderEntity,

                              @WebParam(name = "To", header = true, targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                              final String receiverEntity,

                              @WebParam(name = "relatesTo", header = true,
                                      targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                              final String messageId,
                              // WSA: Action
                              @WebParam(name = "Action", header = true, mode = WebParam.Mode.INOUT,
                                      targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                              final Holder<String> messageType,
                              @WebParam(name = "ProcessingStart", targetNamespace = "http://namespaces.gsma" +
                                      ".org/esim-messaging/1")
                                      XMLGregorianCalendar processingStart,
                              @WebParam(name = "ProcessingEnd")
                                      XMLGregorianCalendar processingEnd,
                              @WebParam(name = "AcceptableValidityPeriod", targetNamespace = "http://namespaces.gsma" +
                                      ".org/esim-messaging/1")
                                      long acceptablevalidity,
                              @WebParam(name = "FunctionExecutionStatus", targetNamespace = "http://namespaces.gsma" +
                                      ".org/esim-messaging/1")
                                      BaseResponseType.ExecutionStatus executionStatus,

                              @WebParam(name = "EuiccResponseData", targetNamespace = "http://namespaces.gsma" +
                                      ".org/esim-messaging/1")
                                      String data

    ) throws Exception {
        po.doTransaction((p1,em) -> {CommonImpl.ISDPstatusChangeresponseHandler(em,messageId, ChangeProfileStatusTransaction.Action.DELETE, executionStatus,data); return true;});

        WSUtils.getRespObject(context).sendError(Response.Status.ACCEPTED.getStatusCode(), "");

        return "";
    }
}
