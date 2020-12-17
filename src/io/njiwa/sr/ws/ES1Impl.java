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
import io.njiwa.common.model.RpaEntity;
import io.njiwa.common.ws.handlers.Authenticator;
import io.njiwa.common.ws.types.BaseResponseType;
import io.njiwa.common.ws.types.WsaEndPointReference;
import io.njiwa.sr.ws.handlers.ES1SignatureVerifyHandler;
import io.njiwa.sr.ws.types.Eis;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.annotation.Resource;
import javax.ejb.Stateless;
import javax.inject.Inject;
import javax.jws.*;
import javax.jws.soap.SOAPBinding;
import javax.persistence.EntityManager;
import javax.xml.ws.Action;
import javax.xml.ws.Holder;
import javax.xml.ws.WebServiceContext;
import java.security.Security;
import java.util.Calendar;
import java.util.Date;

/**
 * Created by bagyenda on 22/04/2016.
 * <p/>
 * All ES1 functions
 */
@WebService(name = "ES1", serviceName = Authenticator.SMSR_SERVICE_NAME,
        targetNamespace = "http://namespaces.gsma.org/esim-messaging/1")
@SOAPBinding(style = SOAPBinding.Style.RPC, use = SOAPBinding.Use.LITERAL)
@HandlerChain(file = "handlers/es1-soap-handler-chain.xml")
@Stateless
public class ES1Impl {
    @Inject
    PersistenceUtility po; // For saving objects
    @Resource
    private WebServiceContext context;

    private String getSenderEUM() {
        RpaEntity entity = Authenticator.getUser(context);
        return entity.getType() == RpaEntity.Type.EUM ? entity.getOid() : null;
    }

    @WebMethod(operationName = "RegisterEIS")
    @Action(input = "http://gsma.com/ES1/eUICCManagement/ES1-RegisterEISRequest",
            output = "http://gsma.com/ES1/eUICCManagement/ES1-RegisterEISResponse")
    @WebResult(name="FunctionExecutionStatus")
    public BaseResponseType registerEIS(
            @WebParam(name = "From", header = true, targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
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

            @WebParam(name="Eis") final
            Eis eis,
            @WebParam(name="RelatesTo",mode = WebParam.Mode.OUT,header = true,
                    targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
           Holder<String> relatesTo
    ) {
        relatesTo.value = messageId;
        messageType.value = "http://gsma.com/ES1/eUICCManagement/ES1-RegisterEISResponse";
        // EIS signature is OK by now, and chain is satisfied. Right?



        Date startDate = Calendar.getInstance().getTime();
        BaseResponseType.ExecutionStatus.Status status = BaseResponseType.ExecutionStatus.Status.ExecutedSuccess;
        final BaseResponseType.ExecutionStatus.StatusCode statusCode = new BaseResponseType.ExecutionStatus.StatusCode("8" +
                ".1","RegisterEIS","","");
        try {
            String eumName = getSenderEUM();
            if (eumName == null)
                throw new Exception("Invalid. Not an EUM");
            String signedInfo = ES1SignatureVerifyHandler.getSignedInfoXML(context.getMessageContext());
            String signature = ES1SignatureVerifyHandler.getSignatureXML(context.getMessageContext());
            // Make model.EIS and save
            final io.njiwa.sr.model.Eis eisObj = eis.toModel(signedInfo,signature);
            po.doTransaction((PersistenceUtility.Runner<Object>) (po, em) -> {
                em.persist(eisObj);
                return true;
            });
        } catch (Exception ex) {
            status = BaseResponseType.ExecutionStatus.Status.Failed;
            statusCode.message = ex.toString();
            statusCode.reasonCode = "4.2";
        }
        Date endDate = Calendar.getInstance().getTime();
        BaseResponseType.ExecutionStatus executionStatus = new BaseResponseType.ExecutionStatus(status,
                statusCode);

            return new BaseResponseType(startDate, endDate, validityPeriod, executionStatus);

    }

    static {
        // Add Bouncy Castle
        Security.addProvider(new BouncyCastleProvider());
    }
}
