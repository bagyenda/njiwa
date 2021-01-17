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

import io.njiwa.common.model.Certificate;
import io.njiwa.common.model.RpaEntity;
import io.njiwa.common.PersistenceUtility;
import io.njiwa.common.Utils;
import io.njiwa.common.model.TransactionType;
import io.njiwa.common.ws.WSUtils;
import io.njiwa.common.ws.handlers.Authenticator;
import io.njiwa.common.ws.types.BaseResponseType;
import io.njiwa.common.ws.types.WsaEndPointReference;
import io.njiwa.sr.model.SmSrTransaction;
import io.njiwa.sr.transactions.EISHandoverTransaction;
import io.njiwa.sr.transactions.ReceiveEISHandoverTransaction;
import io.njiwa.sr.ws.interfaces.ES4;
import io.njiwa.sr.ws.interfaces.ES7;
import io.njiwa.sr.ws.types.AuthenticateSMSRResponse;
import io.njiwa.sr.ws.types.CreateAdditionalKeySetResponse;
import io.njiwa.sr.ws.types.Eis;

import javax.annotation.Resource;
import javax.ejb.Stateless;
import javax.enterprise.concurrent.ManagedExecutorService;
import javax.inject.Inject;
import javax.jws.HandlerChain;
import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebService;
import javax.jws.soap.SOAPBinding;
import javax.persistence.EntityManager;
import javax.persistence.LockModeType;
import javax.ws.rs.core.Response;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.ws.Action;
import javax.xml.ws.Holder;
import javax.xml.ws.WebServiceContext;
import java.io.ByteArrayOutputStream;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Calendar;
import java.util.Date;

/**
 * Created by bagyenda on 09/05/2017.
 */
@WebService(name = "ES7",serviceName = Authenticator.SMSR_SERVICE_NAME, targetNamespace = "http://namespaces.gsma.org/esim-messaging/1")
@SOAPBinding(style = SOAPBinding.Style.RPC, use = SOAPBinding.Use.LITERAL)
@Stateless
@HandlerChain(file = "../../common/ws/handlers/ws-default-handler-chain.xml")
public class ES7Impl {
    @Inject
    PersistenceUtility po; // For saving objects
    @Resource
    private WebServiceContext context;

    @Resource
    private ManagedExecutorService runner; //!< For use by async callbacks

    @Action(input = "http://gsma.com/ES7/eUICCManagement/ES7-HandoverEUICC")
    @WebMethod(operationName = "HandoverEUICC")
    public BaseResponseType handoverEuicc(@WebParam(name = "From", header = true, targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
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

                                          @WebParam(name = "Eis") final
                                              Eis eis,
                                          @WebParam(name = "RelatesTo", mode = WebParam.Mode.OUT, header = true,
                                                  targetNamespace = "http://www.w3.org/2007/05/addressing/metadata")
                                          Holder<String> relatesTo
    ) {
        Date startTime = Calendar.getInstance().getTime();
        final BaseResponseType.ExecutionStatus status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.ExecutedSuccess,
                new BaseResponseType.ExecutionStatus.StatusCode("8" +
                        ".1.1", "handoverEuicc", "", ""));
        String msg = "";

        // Validate ECASD certificate date

        Eis.SecurityDomain.KeySet.Certificate cert = null;
        Certificate.Data certData = null;
        try {
            for (Eis.SecurityDomain.KeySet k : eis.signedInfo.ecasd.keySets)
                if (k.type == Eis.SecurityDomain.KeySet.Type.CA) {
                    cert = k.certificates.get(0); // First one. Right?
                    certData = Certificate.Data.decode(cert.value); // Decode value
                    break;
                }
        } catch (Exception ex) {
        }

        if (certData == null || (certData.expireDate != null && startTime.after(certData.expireDate))) {
            status.status = BaseResponseType.ExecutionStatus.Status.Failed;
            status.statusCodeData.subjectCode = "8.5.2";
            status.statusCodeData.reasonCode = "6.3";
            status.statusCodeData.message = "Invalid ECASD certificate";
        }
        // Get Eum

        final Certificate.Data xcertData = certData;
        if (certData.publicKeyQ != null)
            // Look for the preparehandover
            po.doTransaction((po, em) -> {
                SmSrTransaction tr = SmSrTransaction.findTransaction(em, eis.signedInfo.eid,
                        ES4.ES4_PREPARE_SMSRCHANGE,
                        SmSrTransaction.Status.Ready);
                try {
                    RpaEntity eum = RpaEntity.getByOID(em, eis.signedInfo.eumId, RpaEntity.Type.EUM);
                    if (eum == null)
                        throw new Exception("Invalid. No such EUM");
                    // Assume it has been validated.
                    X509Certificate x509Certificate = eum.secureMessagingCert();
// Get certificate.
                    ECPublicKey pkey = (ECPublicKey) x509Certificate.getPublicKey();
                    // Verify signature.
                    byte[] sdata = xcertData.makeCertificateSigData();
                    boolean verified = Utils.ECC.Signature.verify(pkey, xcertData.signature, sdata);
                    if (!verified)
                        throw new Exception("Invalid: Signature verification failed");
                    // Look for Object
                    ReceiveEISHandoverTransaction trObj = (ReceiveEISHandoverTransaction) tr.getTransObject();
                    if (trObj.stage != ReceiveEISHandoverTransaction.Stage.START)
                        throw new Exception("Invalid state");
                    trObj.eis = eis; // Store eis
                    trObj.pk_ecasd_ecka = xcertData.publicKeyQ;
                    trObj.pk_ecasd_param = xcertData.publicKeyReferenceParam;
                    trObj.oldSmsR = Authenticator.getUser(context).getOid(); // Store old SMSRId
                    trObj.stage = trObj.stage.next(); // Push to next stage
                    tr.setNextSend(startTime); // Send out immediately
                } catch (Exception ex) {
                    status.status = BaseResponseType.ExecutionStatus.Status.Failed;
                    status.statusCodeData.subjectCode = "8.1.1";
                    status.statusCodeData.reasonCode = "1.1";
                    status.statusCodeData.message = msg;
                    Utils.lg.severe(String.format("Error in ES4.handover: %s", ex));
                    return null;
                }
                return tr.getId();
            });
        return new BaseResponseType(startTime, Calendar.getInstance().getTime(), validityPeriod, status);
    }

    @WebMethod(operationName = "AuthenticateSMSRResponse")
    @Action(input = "http://gsma.com/ES7/eUICCManagementCallBack/ES7-AuthenticateSMSR")
    public BaseResponseType authenticateSMSRResponse(@WebParam(name = "From", header = true, targetNamespace =
            "http://www" +
                    ".w3" +
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
                                                     @WebParam(name = "RandomChallenge", targetNamespace = "http://namespaces.gsma" +
                                                             ".org/esim-messaging/1")
                                                     String randomChallenge
    ) {
        Date startTime = Calendar.getInstance().getTime();
        final BaseResponseType.ExecutionStatus status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.ExecutedSuccess,
                new BaseResponseType.ExecutionStatus.StatusCode("8" +
                        ".1.1", "AuthenticateSMSRResponse", "", ""));


        // Get the transaction
        po.doTransaction(new PersistenceUtility.Runner<Object>() {
            @Override
            public Object run(PersistenceUtility po, EntityManager em) throws Exception {
                // Look for transaction
                SmSrTransaction tr = SmSrTransaction.fromMessageID(em, messageId); // Get from message ID
                if (tr != null) {
                    status.status = BaseResponseType.ExecutionStatus.Status.Failed;
                    return null;
                }
                if (executionStatus.status != BaseResponseType.ExecutionStatus.Status.ExecutedSuccess) {
                    tr.updateStatus(em, SmSrTransaction.Status.Failed);
                    tr.setLastupdate(Calendar.getInstance().getTime());
                    tr.setSimResponse(executionStatus.toString());
                    return null;
                }
                ReceiveEISHandoverTransaction trObj = (ReceiveEISHandoverTransaction) tr.getTransObject();
                byte[] xrandomChallenge = Utils.HEX.h2b(randomChallenge);
                trObj.handleResponse(em, tr.getId(), TransactionType.ResponseType.SUCCESS, messageId, xrandomChallenge);
                return null;
            }

            @Override
            public void cleanup(boolean success) {

            }
        });

        return new BaseResponseType(startTime, Calendar.getInstance().getTime(), acceptablevalidity, status);
    }

    @WebMethod(operationName = "CreateAdditionalKeySetResponse")
    @Action(input = "http://gsma.com/ES7/eUICCManagementCallBack/ES7- CreateAdditionalKeySet")
    public BaseResponseType createAdditionalKeysetResponse(@WebParam(name = "From", header = true, targetNamespace =
            "http://www.w3" +
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
                                                           @WebParam(name = "DerivationRandom", targetNamespace =
                                                                   "http://namespaces.gsma" +
                                                                           ".org/esim-messaging/1")
                                                           String dr,
                                                           @WebParam(name = "Receipt", targetNamespace = "http://namespaces" +
                                                                   ".gsma" +
                                                                   ".org/esim-messaging/1")
                                                           String receipt
    ) {

        Date startTime = Calendar.getInstance().getTime();
        final BaseResponseType.ExecutionStatus status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.ExecutedSuccess,
                new BaseResponseType.ExecutionStatus.StatusCode("8" +
                        ".1.1", "CreateAdditionalKeyset", "", ""));
        po.doTransaction(new PersistenceUtility.Runner<Object>() {
            @Override
            public Object run(PersistenceUtility po, EntityManager em) throws Exception {
                // Look for transaction
                SmSrTransaction tr = SmSrTransaction.fromMessageID(em, messageId); // Get from message ID
                if (tr != null) {
                    status.status = BaseResponseType.ExecutionStatus.Status.Failed;
                    return null;
                }
                if (executionStatus.status != BaseResponseType.ExecutionStatus.Status.ExecutedSuccess) {
                    tr.updateStatus(em, SmSrTransaction.Status.Failed);
                    tr.setLastupdate(Calendar.getInstance().getTime());
                    tr.setSimResponse(executionStatus.toString());
                    return null;
                }
                ReceiveEISHandoverTransaction trObj = (ReceiveEISHandoverTransaction) tr.getTransObject();
                byte[] xreceipt = Utils.HEX.h2b(receipt);
                byte[] xdr = Utils.HEX.h2b(dr);
                trObj.handleResponse(em, tr.getId(), TransactionType.ResponseType.SUCCESS, messageId,
                        new ByteArrayOutputStream() {
                            {
                                write(xreceipt);
                                write(xdr);
                            }
                        }.toByteArray());


                return null;
            }

            @Override
            public void cleanup(boolean success) {

            }
        });

        return new BaseResponseType(startTime, Calendar.getInstance().getTime(), acceptablevalidity, status);
    }

    @WebMethod(operationName = "AuthenticateSMSRRequest")
    @Action(input = "http://gsma.com/ES7/eUICCManagement/ES7-AuthenticateSMSR")
    public AuthenticateSMSRResponse authenticateSMSR(@WebParam(name = "From", header = true, targetNamespace = "http://www" +
            ".w3" +
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
                                                     @WebParam(name = "AcceptableValidityPeriod", targetNamespace = "http://namespaces.gsma" +
                                                             ".org/esim-messaging/1")
                                                     long acceptablevalidity,

                                                     @WebParam(name = "Eid", targetNamespace = "http://namespaces.gsma" +
                                                             ".org/esim-messaging/1")
                                                     String eid,
                                                     @WebParam(name = "SmsrCertificate", targetNamespace = "http://namespaces" +
                                                             ".gsma" +
                                                             ".org/esim-messaging/1")
                                                     String smsRCertificate
    ) {
        final BaseResponseType.ExecutionStatus status = new BaseResponseType.ExecutionStatus(BaseResponseType
                .ExecutionStatus.Status.ExecutedSuccess);
        final RpaEntity sender = Authenticator.getUser(context);
        Date startDate = Calendar.getInstance().getTime();

        Long tr = null;
        // Check for EID
        io.njiwa.sr.model.Eis eis = io.njiwa.sr.model.Eis.findByEid(po, eid);
        if (eis == null) {
            status.status = BaseResponseType.ExecutionStatus.Status.Failed;
            status.statusCodeData.message = "EIS does not exist";
            status.statusCodeData.subjectCode = "8.1.1";
            status.statusCodeData.reasonCode = "1.1";
        } else
            tr = po.doTransaction(new PersistenceUtility.Runner<Long>() {
                @Override
                public Long run(PersistenceUtility po, EntityManager em) throws Exception {
                    // Find the pending transaction
                    if (!eis.verifyPendingEuiCCHandoverTransaction(em)) {
                        status.status = BaseResponseType.ExecutionStatus.Status.Failed;
                        status.statusCodeData.message = "EIS handover does not exist";
                        status.statusCodeData.subjectCode = "8.1.1";
                        status.statusCodeData.reasonCode = "1.1";
                        return null;
                    }
                    // Verify certificate
                    Certificate.Data certData;
                    try {
                        certData = Certificate.Data.decode(smsRCertificate);

                        if (certData == null || (certData.expireDate != null && startDate.after(certData.expireDate))) {
                            certData = null;
                        }
                    } catch (Exception ex) {
                        certData = null;
                    }

                    // Get the transaction
                    SmSrTransaction tr = em.find(SmSrTransaction.class, eis.getPendingEuiccHandoverTransaction(), LockModeType.PESSIMISTIC_WRITE);
                    EISHandoverTransaction trObj;
                    try {
                        trObj = (EISHandoverTransaction) tr.getTransObject();
                        if (trObj.stage != EISHandoverTransaction.Stage.HANDOVER_EUICC || sender.getId() != trObj.targetSMSr)
                            throw new Exception("Invalid state or sender");
                    } catch (Exception ex) {
                        status.status = BaseResponseType.ExecutionStatus.Status.Failed;
                        status.statusCodeData.message = "EIS handover error: " + ex.getMessage();
                        status.statusCodeData.subjectCode = "8.1.1";
                        status.statusCodeData.reasonCode = "1.1";
                        return null;
                    }

                    if (certData == null) {
                        status.status = BaseResponseType.ExecutionStatus.Status.Failed;
                        status.statusCodeData.subjectCode = "8.5.3";
                        status.statusCodeData.reasonCode = "6.3";
                        status.statusCodeData.message = "Invalid ECASD certificate";
                        // XXX May be we should expire right away?
                        tr.updateStatus(em, SmSrTransaction.Status.Error);
                        return null;
                    }

                    try {
                        byte[] cert = Utils.HEX.h2b(smsRCertificate); // Get certificate in byte form.
                        trObj.handleResponse(em, tr.getId(), TransactionType.ResponseType.SUCCESS, null, cert); //
                        // Process the cert, let it handle the rest
                        if (trObj.stage == EISHandoverTransaction.Stage.ERROR) {
                            status.status = BaseResponseType.ExecutionStatus.Status.Failed;
                            status.statusCodeData.message = "EIS handover error: failed to validate certificate ";
                            status.statusCodeData.subjectCode = "8.1.1";
                            status.statusCodeData.reasonCode = "1.1";
                            return null;
                        }
                    } catch (Exception ex) {
                    }
                    return tr.getId();
                }

                @Override
                public void cleanup(boolean success) {

                }
            });

        if (tr != null)
            try {
                // Send 202
                WSUtils.getRespObject(context).sendError(Response.Status.ACCEPTED.getStatusCode(), "");
                return null;
            } catch (Exception ex) {
                return null;
            }

        return new AuthenticateSMSRResponse(startDate, Calendar.getInstance().getTime(), acceptablevalidity, status, null);
    }

    @WebMethod(operationName = "CreateAdditionalKeySetRequest")
    @Action(input = "http://gsma.com/ES7/eUICCManagement/ES7-CreateAdditionalKeySet")
    public CreateAdditionalKeySetResponse createAdditionalKeySet(@WebParam(name = "From", header = true,
            targetNamespace =
                    "http://www" +
                            ".w3" +
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
                                                                 @WebParam(name = "AcceptableValidityPeriod", targetNamespace = "http://namespaces.gsma" +
                                                                         ".org/esim-messaging/1")
                                                                 long acceptablevalidity,

                                                                 @WebParam(name = "Eid", targetNamespace = "http://namespaces.gsma" +
                                                                         ".org/esim-messaging/1")
                                                                 String eid,
                                                                 @WebParam(name = "KeyVersionNumber", targetNamespace = "http://namespaces" +
                                                                         ".gsma" +
                                                                         ".org/esim-messaging/1")
                                                                 int keyVersionNumber,
                                                                 @WebParam(name = "InitialSequenceCounter", targetNamespace =
                                                                         "http://namespaces" +
                                                                                 ".gsma" +
                                                                                 ".org/esim-messaging/1")
                                                                 int seqNumber,
                                                                 @WebParam(name = "ECCKeyLength", targetNamespace =
                                                                         "http://namespaces" +
                                                                                 ".gsma" +
                                                                                 ".org/esim-messaging/1")
                                                                 String eccLength,
                                                                 @WebParam(name = "ScenarioParameter", targetNamespace =
                                                                         "http://namespaces" +
                                                                                 ".gsma" +
                                                                                 ".org/esim-messaging/1")
                                                                 byte scenarioParam,
                                                                 @WebParam(name = "HostID", targetNamespace = "http://namespaces" +
                                                                         ".gsma" +
                                                                         ".org/esim-messaging/1")
                                                                 String hostID,
                                                                 @WebParam(name = "EphemeralPublicKey", targetNamespace =
                                                                         "http://namespaces" +
                                                                                 ".gsma" +
                                                                                 ".org/esim-messaging/1")
                                                                 String ePk,
                                                                 @WebParam(name = "Signature", targetNamespace = "http://namespaces" +
                                                                         ".gsma" +
                                                                         ".org/esim-messaging/1")
                                                                 String signature) {
        final BaseResponseType.ExecutionStatus status = new BaseResponseType.ExecutionStatus(BaseResponseType
                .ExecutionStatus.Status.ExecutedSuccess);
        final RpaEntity sender = Authenticator.getUser(context);
        Date startDate = Calendar.getInstance().getTime();

        Long tr = null;
        // Check for EID
        io.njiwa.sr.model.Eis eis = io.njiwa.sr.model.Eis.findByEid(po, eid);
        if (eis == null) {
            status.status = BaseResponseType.ExecutionStatus.Status.Failed;
            status.statusCodeData.message = "EIS does not exist";
            status.statusCodeData.subjectCode = "8.1.1";
            status.statusCodeData.reasonCode = "1.1";
        } else
            tr = po.doTransaction(new PersistenceUtility.Runner<Long>() {
                @Override
                public Long run(PersistenceUtility po, EntityManager em) throws Exception {
                    // Find the pending transaction
                    if (!eis.verifyPendingEuiCCHandoverTransaction(em)) {
                        status.status = BaseResponseType.ExecutionStatus.Status.Failed;
                        status.statusCodeData.message = "EIS handover does not exist";
                        status.statusCodeData.subjectCode = "8.1.1";
                        status.statusCodeData.reasonCode = "1.1";
                        return null;
                    }
                    // Get the transaction
                    SmSrTransaction tr = em.find(SmSrTransaction.class, eis.getPendingEuiccHandoverTransaction(), LockModeType.PESSIMISTIC_WRITE);
                    EISHandoverTransaction trObj;
                    try {
                        trObj = (EISHandoverTransaction) tr.getTransObject();
                        if (trObj.stage != EISHandoverTransaction.Stage.CREATE_ADDITIONAL_KEYSET || sender.getId() != trObj.targetSMSr)
                            throw new Exception("Invalid state or sender");
                    } catch (Exception ex) {
                        status.status = BaseResponseType.ExecutionStatus.Status.Failed;
                        status.statusCodeData.message = "EIS handover error: " + ex.getMessage();
                        status.statusCodeData.subjectCode = "8.1.1";
                        status.statusCodeData.reasonCode = "1.1";
                        return null;
                    }
// Set params
                    trObj.ePk = Utils.HEX.h2b(ePk); // Encoded as per our tables 4-26 of GPC Ammend A
                    trObj.hostID = Utils.HEX.h2b(hostID);
                    trObj.scenarioParam = scenarioParam;
                    trObj.signature = Utils.HEX.h2b(signature);
                    trObj.keyVersionNumber = keyVersionNumber;
                    trObj.sequenceNumber = seqNumber;
                    if (eccLength.contains("384"))
                        trObj.eccLength = 384;
                    else if (eccLength.contains("521"))
                        trObj.eccLength = 521;
                    else if (eccLength.contains("512"))
                        trObj.eccLength = 512;
                    else
                        trObj.eccLength = 256;
                    tr.markReadyToSend();
                    return tr.getId();
                }

                @Override
                public void cleanup(boolean success) {

                }
            });
        if (tr != null)
            try {
                // Send 202
                WSUtils.getRespObject(context).sendError(Response.Status.ACCEPTED.getStatusCode(), "");
                return null;
            } catch (Exception ex) {
                return null;
            }
        return new CreateAdditionalKeySetResponse(startDate, Calendar.getInstance().getTime(), acceptablevalidity,
                status, null, null);
    }

    @WebMethod(operationName = "HandoverEUICCResponse")
    @Action(input = "http://gsma.com/ES7/eUICCManagementCallBack/ES7-HandoverEUICC")
  public   BaseResponseType handoverEUICCResponse(@WebParam(name = "From", header = true, targetNamespace =
            "http://www.w3" +
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
                                           BaseResponseType.ExecutionStatus executionStatus
    ){
        Date startTime = Calendar.getInstance().getTime();
        final BaseResponseType.ExecutionStatus status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.ExecutedSuccess,
                new BaseResponseType.ExecutionStatus.StatusCode("8" +
                        ".1.1", "HandoverEuicc", "", ""));
        final RpaEntity sender = Authenticator.getUser(context);
    // Look for it.
        po.doTransaction(new PersistenceUtility.Runner<Object>() {
            @Override
            public Object run(PersistenceUtility po, EntityManager em) throws Exception {
                SmSrTransaction tr = SmSrTransaction.fromMessageID(em,messageId);
                if (tr == null) {
                    status.status = BaseResponseType.ExecutionStatus.Status.Failed;
                    status.statusCodeData.subjectCode = "1.2";
                    status.statusCodeData.reasonCode = "3";
                    status.statusCodeData.message = "Invalid";
                    return null;
                }
                EISHandoverTransaction trObj;
                try {
                    trObj = (EISHandoverTransaction) tr.getTransObject();
                    if (trObj.stage != EISHandoverTransaction.Stage.HANDOVER_SUCCESS || sender.getId() != trObj.targetSMSr)
                        throw new Exception("Invalid state or sender");
                } catch (Exception ex) {
                    status.status = BaseResponseType.ExecutionStatus.Status.Failed;
                    status.statusCodeData.message = "EIS handover error: " + ex.getMessage();
                    status.statusCodeData.subjectCode = "8.1.1";
                    status.statusCodeData.reasonCode = "1.1";
                    return null;
                }
                // Handle success and so forth
                if (executionStatus.status == BaseResponseType.ExecutionStatus.Status.ExecutedSuccess) {
                    tr.markCompleted();
                    trObj.stage = EISHandoverTransaction.Stage.COMPLETE; // Also completed...
                    io.njiwa.sr.model.Eis eis = tr.eisEntry(em);
                    em.remove(eis); // Delete it
                    // Notify SMSR... But... How? Spec doesn't say!
                    long targetSMSR = trObj.targetSMSr;
                } else {
                    tr.markFailed();
                }
                // Notify MNO
                String mnoId = trObj.mnoID;
                runner.submit(() ->
                        po.doTransaction(new PersistenceUtility.Runner<Object>() {
                            @Override
                            public Object run(PersistenceUtility po, EntityManager em) throws Exception {
                                RpaEntity mno = RpaEntity.getByOID(em,mnoId, RpaEntity.Type.MNO);
                                ES4Client.sendSMSChangeResponse(em, executionStatus,
                                        new WsaEndPointReference(mno, "ES4"),
                                        receiverEntity, sender.getId(), trObj.relatesTO, startTime);
                                return null;
                            }

                            @Override
                            public void cleanup(boolean success) {

                            }
                        })
                );
                return null;
            }

            @Override
            public void cleanup(boolean success) {

            }
        });
        return new BaseResponseType(startTime,Calendar.getInstance().getTime(),acceptablevalidity,status);
    }

    public static class ES7Client {

        public static BaseResponseType sendAuthenticateSMSR(EntityManager em,
                                                            WsaEndPointReference sendTo, String originallyTo,
                                                            Long requestingEntityId, String requestID,
                                                            String eid,
                                                            byte[] certificate) {

            ES7 proxy = WSUtils.getPort("http://namespaces.gsma.org/esim-messaging/1", "ES7Port", sendTo, ES7.class,
                    RpaEntity.Type.SMSR, em,requestingEntityId);
            final WsaEndPointReference sender = new WsaEndPointReference(originallyTo);
            final Holder<String> msgType = new Holder<String>("http://gsma.com/ES7/eUICCManagement/ES7-AuthenticateSMSR");
            try {

                return proxy.authenticateSMSR(sender, sendTo.address, requestID, msgType,
                        TransactionType.DEFAULT_VALIDITY_PERIOD,
                        eid, Utils.HEX.b2H(certificate));

            } catch (WSUtils.SuppressClientWSRequest s) {
            } catch (Exception ex) {
                Utils.lg.severe("Failed to issue async SMSR Authenticate SMSR call: " + ex.getMessage());
                return new BaseResponseType(Calendar.getInstance().getTime(), Calendar.getInstance().getTime(), 0,
                        new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                                new BaseResponseType.ExecutionStatus.StatusCode("", "", "", ex.getMessage())));
            }
            return null;
        }

        public static BaseResponseType sendCreateAdditionalKeySet(EntityManager em,
                                                                  WsaEndPointReference sendTo, String originallyTo,
                                                                  Long requestingEntityId,
                                                                  String requestID,
                                                                  String eid,
                                                                  int keyVersion,
                                                                  int initialCounter,
                                                                  String eccKeyLength,
                                                                  int scenarioParam,
                                                                  byte[] hostID,
                                                                  byte[] ePk,

                                                                  byte[] signature) {

            ES7 proxy = WSUtils.getPort("http://namespaces.gsma.org/esim-messaging/1", "ES7Port", sendTo, ES7.class,
                    RpaEntity.Type.SMSR, em,requestingEntityId);
            final WsaEndPointReference sender = new WsaEndPointReference(originallyTo);
            final Holder<String> msgType = new Holder<>("http://gsma.com/ES7/eUICCManagement/ES7-CreateAdditionalKeySet");
            try {

                return proxy.createAdditionalKeySet(sender, sendTo.address, requestID, msgType,
                        TransactionType.DEFAULT_VALIDITY_PERIOD,
                        eid, keyVersion, initialCounter, eccKeyLength,
                        (byte) scenarioParam,
                        Utils.HEX.b2H(hostID),
                        Utils.HEX.b2H(ePk),
                        Utils.HEX.b2H(signature));

            } catch (WSUtils.SuppressClientWSRequest s) {
            } catch (Exception ex) {
                Utils.lg.severe("Failed to issue async SMSR Authenticate SMSR call: " + ex.getMessage());
                return new BaseResponseType(Calendar.getInstance().getTime(), Calendar.getInstance().getTime(), 0,
                        new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                                new BaseResponseType.ExecutionStatus.StatusCode("", "", "", ex.getMessage())));
            }
            return null;
        }

        public static void sendHandoverEUICCResponse(EntityManager em,
                                                     BaseResponseType.ExecutionStatus status,
                                                     WsaEndPointReference sendTo, String originallyTo,
                                                     Long requestingEntityId,
                                                     String relatesTO,
                                                     Date startDate) {
            if (status == null) {
                status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                        new BaseResponseType.ExecutionStatus.StatusCode("8.4", "", "4.2", ""));
            }

            Date endDate = Calendar.getInstance().getTime(); // Set it

            ES7 proxy = WSUtils.getPort("http://namespaces.gsma.org/esim-messaging/1", "ES7Port", sendTo, ES7.class,
                    RpaEntity.Type.SMSR, em,requestingEntityId);
            final WsaEndPointReference sender = new WsaEndPointReference(originallyTo);
            final Holder<String> msgType = new Holder<String>("http://gsma.com/ES7/eUICCManagementCallBack/ES7-HandoverEUICC");
            try {

                proxy.handoverEUICCResponse(sender, sendTo.address, relatesTO, msgType,
                        Utils.gregorianCalendarFromDate(startDate), Utils.gregorianCalendarFromDate(endDate),
                        TransactionType.DEFAULT_VALIDITY_PERIOD,
                        status);
            } catch (WSUtils.SuppressClientWSRequest s) {
            } catch (Exception ex) {
                Utils.lg.severe("Failed to issue async SMSR handleEUICC Response: " + ex.getMessage());
            }
        }

        public static boolean sendHandoverEUICC(EntityManager em,
                                                WsaEndPointReference sendTo, String originallyTo,
                                                Long requestingEntityId,
                                                String relatesTO,
                                                String messageId,
                                                io.njiwa.sr.model.Eis eis) {
            ES7 proxy = WSUtils.getPort("http://namespaces.gsma.org/esim-messaging/1", "ES7Port", sendTo, ES7.class,
                    RpaEntity.Type.SMSR, em,requestingEntityId);
            final WsaEndPointReference sender = new WsaEndPointReference(originallyTo);
            final Holder<String> msgType = new Holder<String>("http://gsma.com/ES7/eUICCManagement/ES7-HandoverEUICC");
            try {
                Eis xeis = Eis.fromModel(eis);
                xeis.hideCurrentKeys(); // Clear keys out
                proxy.handoverEuicc(sender, sendTo.makeAddress(), sender, messageId, msgType, messageId, TransactionType
                        .DEFAULT_VALIDITY_PERIOD, xeis, new Holder<>(relatesTO));
            } catch (WSUtils.SuppressClientWSRequest s) {
                return true;
            } catch (Exception ex) {
                Utils.lg.severe("Failed to issue async SMSR handleEUICC Response: " + ex.getMessage());
            }
            return false;
        }


        public static void sendAuthenticateSMSRresponse(EntityManager em,
                                                        BaseResponseType.ExecutionStatus status,
                                                        WsaEndPointReference sendTo, String originallyTo,
                                                        Long requestingEntityId,
                                                        String relatesTO,
                                                        Date startDate,
                                                        byte[] randomChallenge) {
            if (status == null) {
                status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                        new BaseResponseType.ExecutionStatus.StatusCode("8.4", "", "4.2", ""));
                randomChallenge = null; // Don't send it
            }

            Date endDate = Calendar.getInstance().getTime(); // Set it

            ES7 proxy = WSUtils.getPort("http://namespaces.gsma.org/esim-messaging/1", "ES7Port", sendTo, ES7.class,
                    RpaEntity.Type.SMSR, em,requestingEntityId);
            final WsaEndPointReference sender = new WsaEndPointReference(originallyTo);
            final Holder<String> msgType = new Holder<String>("http://gsma" +
                    ".com/ES7/eUICCManagementCallBack/ES7-AuthenticateSMSR");
            try {

                proxy.authenticateSMSRResponse(sender, sendTo.address, relatesTO, msgType,
                        Utils.gregorianCalendarFromDate(startDate), Utils.gregorianCalendarFromDate(endDate),
                        TransactionType.DEFAULT_VALIDITY_PERIOD,
                        status, randomChallenge != null ? Utils.HEX.b2H(randomChallenge) : null);
            } catch (WSUtils.SuppressClientWSRequest s) {
            } catch (Exception ex) {
                Utils.lg.severe("Failed to issue async SMSR authenticateSMSR Response: " + ex.getMessage());
            }
        }

        public static void sendcreateAdditionalKeySetResponse(EntityManager em,
                                                              BaseResponseType.ExecutionStatus status,
                                                              WsaEndPointReference sendTo, String originallyTo,
                                                              Long requestingEntityId,
                                                              String relatesTO,
                                                              Date startDate,
                                                              byte[] receipt, byte[] dr) {
            if (status == null) {
                status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                        new BaseResponseType.ExecutionStatus.StatusCode("8.4", "", "4.2", ""));
            }

            Date endDate = Calendar.getInstance().getTime(); // Set it

            ES7 proxy = WSUtils.getPort("http://namespaces.gsma.org/esim-messaging/1", "ES7Port", sendTo, ES7.class,
                    RpaEntity.Type.SMSR, em,requestingEntityId);
            final WsaEndPointReference sender = new WsaEndPointReference(originallyTo);
            final Holder<String> msgType = new Holder<String>("http://gsma" +
                    ".com/ES7/eUICCManagementCallBack/ES7-CreateAdditionalKeyset");
            try {

                proxy.createAdditionalKeysetResponse(sender, sendTo.address, relatesTO, msgType,
                        Utils.gregorianCalendarFromDate(startDate), Utils.gregorianCalendarFromDate(endDate),
                        TransactionType.DEFAULT_VALIDITY_PERIOD,
                        status, dr != null ? Utils.HEX.b2H(dr) : null,
                        receipt != null ? Utils.HEX.b2H(receipt) : null);
            } catch (WSUtils.SuppressClientWSRequest s) {
            } catch (Exception ex) {
                Utils.lg.severe("Failed to issue async SMSR createAdditionalKeySet Response: " + ex.getMessage());
            }
        }


    }

}
