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

/**
 * Created by bagyenda on 05/04/2017.
 */

import io.njiwa.common.PersistenceUtility;
import io.njiwa.common.Utils;
import io.njiwa.common.model.Certificate;
import io.njiwa.common.model.RpaEntity;
import io.njiwa.common.ws.WSUtils;
import io.njiwa.common.ws.handlers.Authenticator;
import io.njiwa.common.ws.types.BaseResponseType;
import io.njiwa.common.ws.types.WsaEndPointReference;
import io.njiwa.dp.model.Euicc;
import io.njiwa.dp.model.ISDP;
import io.njiwa.dp.model.ProfileTemplate;
import io.njiwa.dp.model.SmDpTransaction;
import io.njiwa.dp.transactions.ChangeProfileStatusTransaction;
import io.njiwa.dp.transactions.DownloadProfileTransaction;
import io.njiwa.dp.transactions.UpdatePolicyRulesTransaction;
import io.njiwa.dp.ws.types.*;
import io.njiwa.sr.ws.types.Eis;
import io.njiwa.sr.ws.types.Pol2Type;

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
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;
import javax.xml.ws.Action;
import javax.xml.ws.Holder;
import javax.xml.ws.WebServiceContext;
import java.util.*;

// Sending of 202 response for Accept, according to:
// http://stackoverflow.com/questions/19297722/how-to-make-jax-ws-webservice-respond-with-specific-http-code
@WebService(name = "ES2", targetNamespace = "http://namespaces.gsma.org/esim-messaging/1", serviceName =
        Authenticator.SMDP_SERVICE_NAME)
@SOAPBinding(style = SOAPBinding.Style.RPC, use = SOAPBinding.Use.LITERAL)
@Stateless
@HandlerChain(file = "../../common/ws/handlers/ws-default-handler-chain.xml")
public class ES2Impl {
    @Inject
    PersistenceUtility po; // For saving objects
    @Resource
    private ManagedExecutorService runner; //!< For use by async callbacks
    @Resource
    private WebServiceContext context;

    @WebMethod(operationName = "GetEIS")
    @Action(input = "http://gsma.com/ES2/ProfileManagent/ES2-GetEISRequest", output = "http://gsma" +
            ".com/ES2/ProfileManagent/ES2-GetEISResponse")
    public GetEISResponse getEIS(@WebParam(name = "From", header = true, targetNamespace = "http://www.w3" + ".org" +
            "/2007/05/addressing/metadata") WsaEndPointReference senderEntity,

                                 @WebParam(name = "To", header = true, targetNamespace = "http://www.w3" +
                                         ".org/2007/05/addressing/metadata") String receiverEntity, @WebParam(name =
            "ReplyTo", header = true, targetNamespace = "http://www.w3" + ".org/2007/05/addressing/metadata") WsaEndPointReference replyTo, @WebParam(name = "MessageID", header = true, targetNamespace = "http://www.w3.org/2007/05/addressing/metadata") String messageId,
                                 // WSA: Action
                                 @WebParam(name = "Action", header = true, mode = WebParam.Mode.INOUT,
                                         targetNamespace = "http://www.w3.org/2007/05/addressing/metadata") Holder<String> messageType,

                                 // These are in the body
                                 @WebParam(name = "FunctionCallIdentifier") String functionCallId,

                                 @WebParam(name = "ValidityPeriod") long validityPeriod,

                                 @WebParam(name = "Eid") final String eid,
                                 @WebParam(name = "Smsr-id") final String smsrId, @WebParam(name = "RelatesTo", mode
            = WebParam.Mode.OUT, header = true, targetNamespace = "http://www.w3.org/2007/05/addressing/metadata") Holder<String> relatesTo) {
// Assume synchronous. Right?
        relatesTo.value = messageId;
        messageType.value = "http://gsma.com/ES3/ProfileManagent/ES3-GetEISResponse";

        Date startDate = Calendar.getInstance().getTime();
        BaseResponseType.ExecutionStatus.Status status;
        BaseResponseType.ExecutionStatus.StatusCode statusCode =
                new BaseResponseType.ExecutionStatus.StatusCode("8" + ".1.1", "GetEIS", "", "");

        Eis eis = null;
        final RpaEntity smsr;
        try {
            // Find the SM-SR
            smsr = RpaEntity.getByOID(po, smsrId, RpaEntity.Type.SMSR);
        } catch (Exception ex) {
            statusCode.reasonCode = "3.9";
            statusCode.subjectIdentifier = "SM-SR";
            statusCode.subjectCode = "8.7";
            statusCode.message = "Unknown SM-SR";
            return new GetEISResponse(startDate, Calendar.getInstance().getTime(), validityPeriod,
                    new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed, statusCode),
                    null);
        }

        // We have it. Get it's URL, call the SMS-SR, get back a response...
        try {
            // final RpaEntity myRpa = WSUtils.getMyRpa(po, RpaEntity.Type.SMDP);
            final String xrelatesTo = UUID.randomUUID().toString();
            io.njiwa.sr.ws.types.GetEISResponse response = po.doTransaction((po, em) -> ES2Client.getEIS(em, smsr,
                    xrelatesTo, eid));

            statusCode = response.functionExecutionStatus.statusCodeData;
            status = response.functionExecutionStatus.status;
            eis = response.eis;
        } catch (Exception ex) {
            status = BaseResponseType.ExecutionStatus.Status.Failed;

        }
        return new GetEISResponse(startDate, Calendar.getInstance().getTime(), validityPeriod,
                new BaseResponseType.ExecutionStatus(status, statusCode), eis);
    }

    private Euicc findOrFetchEIS(final RpaEntity smsr, final String eid) {
        return po.doTransaction((po, em) ->  findOrFetchEIS(em,smsr,eid));
    }

    private Euicc findOrFetchEIS(EntityManager em, final RpaEntity smsr, final String eid)
    {
        Eis eis = ES2Client.getEIS(em, smsr, eid);
        if (eis != null) {
            // Make a new one and save it.
            Eis.SecurityDomain ecasd = eis.signedInfo.ecasd;

            byte[] ecasd_pKey = null;
            int ecasd_pref = 0;
            // Find ecasd pub key and key param
            try {

                for (Eis.SecurityDomain.KeySet k : ecasd.keySets)
                    if (k.type == Eis.SecurityDomain.KeySet.Type.CA) {

                        // Go over the keysets, look for the one we want
                        try {
                            for (Eis.SecurityDomain.KeySet.Certificate c : k.certificates) {
                                Certificate.Data d = Certificate.Data.decode(c.value);
                                if (d.keyUsage == d.KEYAGREEMENT) {
                                    ecasd_pKey = d.publicKeyQ;
                                    ecasd_pref = d.publicKeyReferenceParam;
                                    break;
                                }
                            }
                        } catch (Exception ex) {
                        }
                        break;
                    }
            } catch (Exception ex) {
            }
            Euicc euicc = Euicc.findByEID(em, eid);
            // Save key information. right?
            if (euicc == null) {
                euicc = new Euicc(eid, smsr.getOid(), new ArrayList<>());
                em.persist(euicc);
            }
            euicc.setEcasd_public_key_param_ref(ecasd_pref);
            euicc.setEcasd_public_key_q(ecasd_pKey);
            // Store them for future reference
            euicc.setIsdR_sdin(eis.isdR.sdin);
            euicc.setIsdR_sin(eis.isdR.sin);
            euicc.eis = eis;

            return euicc;
        }
        return null;
    }

    @WebMethod(operationName = "DownloadProfile")
    @Action(input = "http://gsma.com/ES2/ProfileManagent/ES2-DownloadProfileRequest", output = "http://gsma" +
            ".com/ES2/ProfileManagent/ES2-DownloadProfileResponse")
    public DownloadProfileResponse downloadProfile(@WebParam(name = "From", header = true, targetNamespace = "http" +
            "://www.w3" + ".org/2007/05/addressing/metadata") final WsaEndPointReference senderEntity,

                                                   @WebParam(name = "To", header = true, targetNamespace = "http" +
                                                           "://www.w3.org/2007/05/addressing/metadata") final String receiverEntity, @WebParam(name = "ReplyTo", header = true, targetNamespace = "http://www.w3" + ".org/2007/05/addressing/metadata") final WsaEndPointReference replyTo, @WebParam(name = "MessageID", header = true, targetNamespace = "http://www.w3.org/2007/05/addressing/metadata") final String messageId,
                                                   // WSA: Action
                                                   @WebParam(name = "Action", header = true, mode =
                                                           WebParam.Mode.INOUT, targetNamespace = "http://www.w3" +
                                                           ".org/2007/05/addressing/metadata") Holder<String> messageType,

                                                   // These are in the body
                                                   @WebParam(name = "FunctionCallIdentifier") String functionCallId,

                                                   @WebParam(name = "ValidityPeriod") final long validityPeriod,

                                                   @WebParam(name = "Eid") final String eid, @WebParam(name = "Smsr" +
            "-Id") final String smsrId,

                                                   @WebParam(name = "ProfileType") final String profileType,

                                                   @WebParam(name = "Iccid") final String profileIccid,
                                                   @WebParam(name = "EnableProfile") final boolean enableProfile,
                                                   @WebParam(name = "RelatesTo", mode = WebParam.Mode.OUT, header =
                                                           true, targetNamespace = "http://www.w3" +
                                                           ".org/2007/05/addressing/metadata") Holder<String> relatesTo) throws Exception {
        Date startDate = Calendar.getInstance().getTime();
        final RpaEntity sender = Authenticator.getUser(context); // Get the sender
        final RpaEntity smsr = RpaEntity.getByOID(po, smsrId, RpaEntity.Type.SMSR);

        DownloadProfileResponse resp = po.doTransaction((po, em) -> {
            if (smsr == null)
                return new DownloadProfileResponse(startDate, Calendar.getInstance().getTime(),
                        new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                                new BaseResponseType.ExecutionStatus.StatusCode("8.7", "3.9", "SMS-SR", "Unknown " +
                                        "SM-SR")), null);
            final Euicc euicc = findOrFetchEIS(em, smsr, eid);
            Eis eis = euicc != null ? euicc.eis : null;
            if (eis == null)
                return new DownloadProfileResponse(startDate, Calendar.getInstance().getTime(),
                        new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                                new BaseResponseType.ExecutionStatus.StatusCode("8.1.1", "3.9", "EID", "Unknown EID")), null);

            if (euicc.getEcasd_public_key_q() == null)
                return new DownloadProfileResponse(startDate, Calendar.getInstance().getTime(),
                        new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                                new BaseResponseType.ExecutionStatus.StatusCode("8.1.1", "3.9", "EID", "No ECASD " +
                                        "Cert")), null);

            // Check if the ISDP already exists...
            if (ISDP.find(em, euicc.getId(), profileIccid) != null)
                return new DownloadProfileResponse(startDate, Calendar.getInstance().getTime(),
                        new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                                new BaseResponseType.ExecutionStatus.StatusCode("8.2.1", "1.2", "Profile ICCID", "ISDP exists")), null);

            ProfileTemplate profile;
            boolean byICCID = false;
            // Look for profile

            DownloadProfileResponse resp2 = null;
            if (!Utils.isEmpty(profileIccid)) {
                profile = ProfileTemplate.findByICCID(em, profileIccid, sender.getId());
                if (profile == null)
                    resp2 = new DownloadProfileResponse(startDate, Calendar.getInstance().getTime(),
                            new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                                    new BaseResponseType.ExecutionStatus.StatusCode("8.2.1", "3.9", "Profile ICCID",
                                            "Unknown Profile ICCID")), null);
                byICCID = true;
            } else profile = null;

            if (profile == null && !Utils.isEmpty(profileType)) {
                profile = ProfileTemplate.findByType(em, profileType, sender.getId());
                byICCID = false;
            }

            if (profile == null)
                return resp2 != null ? resp2 : new DownloadProfileResponse(startDate,
                        Calendar.getInstance().getTime(),
                        new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                                new BaseResponseType.ExecutionStatus.StatusCode("8.2.5", "3.9", "Profile Type",
                                        "Unknown Profile Type")), null);


            // Verify template
            int requiredMem = profile.getRequiredMemory();
            long availableMem = eis.availableMemoryForProfiles;
            if (requiredMem > availableMem)
                return new DownloadProfileResponse(startDate, Calendar.getInstance().getTime(),
                        new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                                new BaseResponseType.ExecutionStatus.StatusCode(byICCID ? "8.2.1" : "8.2.5", "2.1",
                                        byICCID ? "Profile ICCID" : "Profile Type", "Insufficient memory on eUICC")),
                        null);
            // Check versions
            String platform = eis.signedInfo.platformType;
            String platformVersion = eis.signedInfo.platformVersion;
            Map<String, String> supportedPlatforms = profile.getSupportedPlatforms();
            if (supportedPlatforms != null && platform != null && supportedPlatforms.size() > 0) {
                String minVer = supportedPlatforms.get(platform);
                if (platformVersion == null) platformVersion = "1.0";
                if (minVer == null)
                    return new DownloadProfileResponse(startDate, Calendar.getInstance().getTime(),
                            new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                                    new BaseResponseType.ExecutionStatus.StatusCode(byICCID ? "8.2.1" : "8.2.5", "2" +
                                            ".1", byICCID ? "Profile ICCID" : "Profile Type", "Unsupported platform " +
                                            "version: " + platform + " v" + platformVersion)), null);
                int x = Utils.compareVersions(Utils.parseVersionString(platformVersion),
                        Utils.parseVersionString(minVer));
                if (x < 0)
                    return new DownloadProfileResponse(startDate, Calendar.getInstance().getTime(),
                            new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                                    new BaseResponseType.ExecutionStatus.StatusCode(byICCID ? "8.2.1" : "8.2.5", "2" +
                                            ".1", byICCID ? "Profile ICCID" : "Profile Type", "Unsupported platform " +
                                            "version: " + platform + " v" + platformVersion + "! Below minimum " +
                                            "required")), null);
            }
            // Now we need to create the transaction
            final ProfileTemplate xprofile = profile;

            SmDpTransaction tr;
            try {
                // Make ISDP
                ISDP xisdp = new ISDP(euicc, sender.getOid(), xprofile);
                List<ISDP> l = euicc.getIsdps();
                if (l == null) l = new ArrayList<>();
                l.add(xisdp);
                euicc.setIsdps(l);
                em.persist(xisdp);
                DownloadProfileTransaction trObj1 = new DownloadProfileTransaction(em, xprofile, euicc, smsr.getId(),
                        enableProfile);
                trObj1.updateBaseData(senderEntity, receiverEntity, messageId, validityPeriod, replyTo,
                        Authenticator.getUser(context).getId());
                tr = new SmDpTransaction(sender, euicc.getId(), validityPeriod, trObj1);
                tr.setIsdp(xisdp); // Record it.
                em.persist(tr);
            } catch (Exception ex) {
                tr = null;
            }
            // em.flush(); // XX Really? So we can check that iccid is unique for this euicc. Right??


            if (tr == null)
                return new DownloadProfileResponse(startDate, Calendar.getInstance().getTime(),
                        new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                                new BaseResponseType.ExecutionStatus.StatusCode(byICCID ? "8.2.1" : "8.2.5", "2.1",
                                        byICCID ? "Profile ICCID" : "Profile Type", "Data preparation failed")), null);
            return null;
        });

        if (resp != null) return resp;

        HttpServletResponse httpResp = WSUtils.getRespObject(context);
        httpResp.sendError(Response.Status.ACCEPTED.getStatusCode(), ""); // Tell sender we are going to reply.
        return null;
    }

    @WebMethod(operationName = "EnableProfile")
    @Action(input = "http://gsma.com/ES2/ProfileManagent/ES2-EnableProfileRequest", output = "http://gsma" +
            ".com/ES2/ProfileManagent/ES2-EnableProfileResponse")
    public EnableProfileResponse enableProfile(@WebParam(name = "From", header = true, targetNamespace = "http://www" +
            ".w3" + ".org/2007/05/addressing/metadata") final WsaEndPointReference senderEntity,

                                               @WebParam(name = "To", header = true, targetNamespace = "http://www.w3" +
                                                       ".org/2007/05/addressing/metadata") final String receiverEntity, @WebParam(name = "ReplyTo", header = true, targetNamespace = "http://www.w3" + ".org/2007/05/addressing/metadata") final WsaEndPointReference replyTo, @WebParam(name = "MessageID", header = true, targetNamespace = "http://www.w3.org/2007/05/addressing/metadata") final String messageId,
                                               // WSA: Action
                                               @WebParam(name = "Action", header = true, mode = WebParam.Mode.INOUT,
                                                       targetNamespace = "http://www.w3.org/2007/05/addressing" +
                                                               "/metadata") Holder<String> messageType,

                                               // These are in the body
                                               @WebParam(name = "FunctionCallIdentifier") String functionCallId,

                                               @WebParam(name = "ValidityPeriod") final long validityPeriod,

                                               @WebParam(name = "Eid") final String eid,
                                               @WebParam(name = "Smsr-id") final String smsrId,


                                               @WebParam(name = "Iccid") final String profileIccid,

                                               @WebParam(name = "RelatesTo", mode = WebParam.Mode.OUT, header = true,
                                                       targetNamespace = "http://www.w3.org/2007/05/addressing" +
                                                               "/metadata") Holder<String> relatesTo) throws Exception {

        Date startDate = Calendar.getInstance().getTime();
        final RpaEntity sender = Authenticator.getUser(context); // Get the sender
        final RpaEntity smsr = RpaEntity.getByOID(po, smsrId, RpaEntity.Type.SMSR);


        if (smsr == null)
            return new EnableProfileResponse(startDate, Calendar.getInstance().getTime(),
                    new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                            new BaseResponseType.ExecutionStatus.StatusCode("8.7", "3.9", "SMS-SR", "Unknown SM-SR")));
        final Euicc euicc = findOrFetchEIS(smsr, eid);
        Eis eis = euicc != null ? euicc.eis : null;
        if (eis == null)
            return new EnableProfileResponse(startDate, Calendar.getInstance().getTime(),
                    new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                            new BaseResponseType.ExecutionStatus.StatusCode("8.1.1", "3.9", "EID", "Unknown EID")));

        // check if we have it
        // Make a profile change status transaction...

        // Now we need to create the transaction
        SmDpTransaction trObj = po.doTransaction((po, em) -> {
            ChangeProfileStatusTransaction trObj1 = new ChangeProfileStatusTransaction(smsr.getId(),
                    ChangeProfileStatusTransaction.Action.ENABLE, profileIccid);
            trObj1.updateBaseData(senderEntity, receiverEntity, messageId, validityPeriod, replyTo,
                    Authenticator.getUser(context).getId());
            SmDpTransaction tr = new SmDpTransaction(sender, euicc.getId(), validityPeriod, trObj1);
            em.persist(tr);
            // em.flush(); // XX Really? So we can check that iccid is unique for this euicc. Right??
            return tr;
        });

        if (trObj == null)
            return new EnableProfileResponse(startDate, Calendar.getInstance().getTime(),
                    new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                            new BaseResponseType.ExecutionStatus.StatusCode("8.2.5", "2.1", "Profile", "Data " +
                                    "preparation failed")));
        WSUtils.getRespObject(context).sendError(Response.Status.ACCEPTED.getStatusCode(), ""); // Tell sender we are
        // going to reply.
        return null;
    }

    @WebMethod(operationName = "DisableProfile")
    @Action(input = "http://gsma.com/ES2/ProfileManagent/ES2-DisableProfileRequest", output = "http://gsma" +
            ".com/ES2/ProfileManagent/ES2-DisableProfileResponse")
    public DisableProfileResponse disableProfile(@WebParam(name = "From", header = true, targetNamespace = "http" +
            "://www.w3" + ".org/2007/05/addressing/metadata") final WsaEndPointReference senderEntity,

                                                 @WebParam(name = "To", header = true, targetNamespace = "http://www" +
                                                         ".w3.org/2007/05/addressing/metadata") final String receiverEntity, @WebParam(name = "ReplyTo", header = true, targetNamespace = "http://www.w3" + ".org/2007/05/addressing/metadata") final WsaEndPointReference replyTo, @WebParam(name = "MessageID", header = true, targetNamespace = "http://www.w3.org/2007/05/addressing/metadata") final String messageId,
                                                 // WSA: Action
                                                 @WebParam(name = "Action", header = true, mode = WebParam.Mode.INOUT
                                                         , targetNamespace = "http://www.w3.org/2007/05/addressing" +
                                                         "/metadata") Holder<String> messageType,

                                                 // These are in the body
                                                 @WebParam(name = "FunctionCallIdentifier") String functionCallId,

                                                 @WebParam(name = "ValidityPeriod") final long validityPeriod,

                                                 @WebParam(name = "Eid") final String eid,
                                                 @WebParam(name = "Smsr-id") final String smsrId,


                                                 @WebParam(name = "Iccid") final String profileIccid,

                                                 @WebParam(name = "RelatesTo", mode = WebParam.Mode.OUT, header =
                                                         true, targetNamespace = "http://www.w3" +
                                                         ".org/2007/05/addressing/metadata") Holder<String> relatesTo) throws Exception {

        Date startDate = Calendar.getInstance().getTime();
        final RpaEntity sender = Authenticator.getUser(context); // Get the sender
        final RpaEntity smsr = RpaEntity.getByOID(po, smsrId, RpaEntity.Type.SMSR);


        if (smsr == null)
            return new DisableProfileResponse(startDate, Calendar.getInstance().getTime(),
                    new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                            new BaseResponseType.ExecutionStatus.StatusCode("8.7", "3.9", "SMS-SR", "Unknown SM-SR")));
        final Euicc euicc = findOrFetchEIS(smsr, eid);
        Eis eis = euicc != null ? euicc.eis : null;
        if (eis == null)
            return new DisableProfileResponse(startDate, Calendar.getInstance().getTime(),
                    new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                            new BaseResponseType.ExecutionStatus.StatusCode("8.1.1", "3.9", "EID", "Unknown EID")));

        // check if we have it
        // Make a profile change status transaction...

        // Now we need to create the transaction
        SmDpTransaction trObj = po.doTransaction((po, em) -> {
            ChangeProfileStatusTransaction trObj1 = new ChangeProfileStatusTransaction(smsr.getId(),
                    ChangeProfileStatusTransaction.Action.DISABLE, profileIccid);
            trObj1.updateBaseData(senderEntity, receiverEntity, messageId, validityPeriod, replyTo,
                    Authenticator.getUser(context).getId());
            SmDpTransaction tr = new SmDpTransaction(sender, euicc.getId(), validityPeriod, trObj1);
            em.persist(tr);
            // em.flush(); // XX Really? So we can check that iccid is unique for this euicc. Right??
            return tr;
        });

        if (trObj == null)
            return new DisableProfileResponse(startDate, Calendar.getInstance().getTime(),
                    new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                            new BaseResponseType.ExecutionStatus.StatusCode("8.2.5", "2.1", "Profile", "Data " +
                                    "preparation failed")));
        WSUtils.getRespObject(context).sendError(Response.Status.ACCEPTED.getStatusCode(), ""); // Tell sender we are
        // going to reply.
        return null;
    }

    @WebMethod(operationName = "UpdatePolicyRules")
    @Action(input = "http://gsma.com/ES2/ProfileManagement/ES2-UpdatePolicyRules", output = "http://gsma" +
            ".com/ES2/ProfileManagement/ES2-UpdatePolicyRules")
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
                                              @WebParam(name = "Iccid") final String iccid, @WebParam(name = "Smsr-Id"
    ) final String smsrId, @WebParam(name = "pol2") final Pol2Type pol2) throws Exception {

        Date startDate = Calendar.getInstance().getTime();
        final RpaEntity sender = Authenticator.getUser(context); // Get the sender
        final RpaEntity smsr = RpaEntity.getByOID(po, smsrId, RpaEntity.Type.SMSR);
        if (smsr == null)
            return new BaseResponseType(startDate, Calendar.getInstance().getTime(), validityPeriod,
                    new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                            new BaseResponseType.ExecutionStatus.StatusCode("8.7", "3.9", "SMS-SR", "Unknown SM-SR")));
        final Euicc euicc = findOrFetchEIS(smsr, eid);
        Eis eis = euicc != null ? euicc.eis : null;
        if (eis == null)
            return new BaseResponseType(startDate, Calendar.getInstance().getTime(), validityPeriod,
                    new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                            new BaseResponseType.ExecutionStatus.StatusCode("8.1.1", "3.9", "EID", "Unknown EID")));


        SmDpTransaction trObj = po.doTransaction((po, em) -> {
            UpdatePolicyRulesTransaction trObj1 = new UpdatePolicyRulesTransaction(smsr.getId(), iccid, pol2);
            trObj1.updateBaseData(senderEntity, receiverEntity, messageId, validityPeriod, replyTo,
                    Authenticator.getUser(context).getId());
            SmDpTransaction tr = new SmDpTransaction(sender, euicc.getId(), validityPeriod, trObj1);
            em.persist(tr);
            // em.flush(); // XX Really? So we can check that iccid is unique for this euicc. Right??
            return tr;
        });

        if (trObj == null)
            return new BaseResponseType(startDate, Calendar.getInstance().getTime(), validityPeriod,
                    new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                            new BaseResponseType.ExecutionStatus.StatusCode("8.2.5", "2.1", "Profile", "Internal " +
                                    "error")));
        WSUtils.getRespObject(context).sendError(Response.Status.ACCEPTED.getStatusCode(), ""); // Tell sender we are
        // going to reply.
        return null;
    }

    @WebMethod(operationName = "DeleteProfile")
    @Action(input = "http://gsma.com/ES2/ProfileManagent/ES2-DeleteProfileRequest", output = "http://gsma" +
            ".com/ES2/ProfileManagent/ES2-DeleteProfileResponse")
    public DeleteProfileResponse deleteProfile(@WebParam(name = "From", header = true, targetNamespace = "http://www" +
            ".w3" + ".org/2007/05/addressing/metadata") final WsaEndPointReference senderEntity,

                                               @WebParam(name = "To", header = true, targetNamespace = "http://www.w3" +
                                                       ".org/2007/05/addressing/metadata") final String receiverEntity, @WebParam(name = "ReplyTo", header = true, targetNamespace = "http://www.w3" + ".org/2007/05/addressing/metadata") final WsaEndPointReference replyTo, @WebParam(name = "MessageID", header = true, targetNamespace = "http://www.w3.org/2007/05/addressing/metadata") final String messageId,
                                               // WSA: Action
                                               @WebParam(name = "Action", header = true, mode = WebParam.Mode.INOUT,
                                                       targetNamespace = "http://www.w3.org/2007/05/addressing" +
                                                               "/metadata") Holder<String> messageType,

                                               // These are in the body
                                               @WebParam(name = "FunctionCallIdentifier") String functionCallId,

                                               @WebParam(name = "ValidityPeriod") final long validityPeriod,

                                               @WebParam(name = "Eid") final String eid,
                                               @WebParam(name = "Smsr-id") final String smsrId,


                                               @WebParam(name = "Iccid") final String profileIccid,

                                               @WebParam(name = "RelatesTo", mode = WebParam.Mode.OUT, header = true,
                                                       targetNamespace = "http://www.w3.org/2007/05/addressing" +
                                                               "/metadata") Holder<String> relatesTo) throws Exception {

        Date startDate = Calendar.getInstance().getTime();
        final RpaEntity sender = Authenticator.getUser(context); // Get the sender
        final RpaEntity smsr = RpaEntity.getByOID(po, smsrId, RpaEntity.Type.SMSR);


        if (smsr == null)
            return new DeleteProfileResponse(startDate, Calendar.getInstance().getTime(),
                    new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                            new BaseResponseType.ExecutionStatus.StatusCode("8.7", "3.9", "SMS-SR", "Unknown SM-SR")));
        final Euicc euicc = findOrFetchEIS(smsr, eid);
        Eis eis = euicc != null ? euicc.eis : null;
        if (eis == null)
            return new DeleteProfileResponse(startDate, Calendar.getInstance().getTime(),
                    new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                            new BaseResponseType.ExecutionStatus.StatusCode("8.1.1", "3.9", "EID", "Unknown EID")));


        SmDpTransaction trObj = po.doTransaction((po, em) -> {
            ChangeProfileStatusTransaction trObj1 = new ChangeProfileStatusTransaction(smsr.getId(),
                    ChangeProfileStatusTransaction.Action.DELETE, profileIccid);
            trObj1.updateBaseData(senderEntity, receiverEntity, messageId, validityPeriod, replyTo,
                    Authenticator.getUser(context).getId());
            SmDpTransaction tr = new SmDpTransaction(sender, euicc.getId(), validityPeriod, trObj1);
            em.persist(tr);
            // em.flush(); // XX Really? So we can check that iccid is unique for this euicc. Right??
            return tr;
        });

        if (trObj == null)
            return new DeleteProfileResponse(startDate, Calendar.getInstance().getTime(),
                    new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                            new BaseResponseType.ExecutionStatus.StatusCode("8.2.5", "2.1", "Profile", "Data " +
                                    "preparation failed")));
        WSUtils.getRespObject(context).sendError(Response.Status.ACCEPTED.getStatusCode(), ""); // Tell sender we are
        // going to reply.
        return null;
    }


}