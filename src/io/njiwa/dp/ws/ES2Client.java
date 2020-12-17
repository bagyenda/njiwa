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
import io.njiwa.common.model.RpaEntity;
import io.njiwa.common.model.TransactionType;
import io.njiwa.dp.ws.interfaces.ES2;
import io.njiwa.common.Utils;
import io.njiwa.common.ws.WSUtils;
import io.njiwa.common.ws.types.BaseResponseType;
import io.njiwa.common.ws.types.WsaEndPointReference;
import io.njiwa.sr.ws.CommonImpl;
import io.njiwa.sr.ws.interfaces.ES3;
import io.njiwa.sr.ws.types.GetEISResponse;
import io.njiwa.sr.ws.types.Eis;

import javax.persistence.EntityManager;
import javax.xml.ws.Holder;
import java.util.Calendar;
import java.util.Date;
import java.util.UUID;

/**
 * Created by bagyenda on 25/05/2017.
 */
public final class ES2Client {

    public static GetEISResponse getEIS(EntityManager em, RpaEntity smsr, String
            relatesTo, String eid) {

        WsaEndPointReference xto = new WsaEndPointReference(smsr,"ES3");
        String to = xto.makeAddress();


        final Holder<String> msgType = new Holder<String>("http://gsma" +
                ".com/ES3/ProfileManagent/ES3-GetEIS");
        try {
            String messageID = UUID.randomUUID().toString();
            GetEISResponse response;
            if (smsr.getId() == RpaEntity.LOCAL_ENTITY_ID) {
                Utils.Triple<BaseResponseType.ExecutionStatus, RpaEntity, Date> p = CommonImpl.makeBaseResp(RpaEntity.getLocal(RpaEntity.Type.SMDP),"8.1.1");
                Eis eis = CommonImpl.getEIS(em,eid, RpaEntity.Type.SMDP,p.l,p.k);
                if (eis == null)
                    p.k.status = BaseResponseType.ExecutionStatus.Status.Failed;
                response = new GetEISResponse(p.m,Calendar.getInstance().getTime(),10,p.k,eis);
            } else {
                ES3 proxy = WSUtils.getPort("http://namespaces.gsma.org/esim-messaging/1", "ES3Port", xto, ES3.class, RpaEntity.Type.SMDP, em, smsr.getId());
                // Leave out optional (Sec B.2.1.1) wsa:From and wsa:ReplyTo
                response = proxy.getEIS(null, to, null, messageID, msgType, messageID, TransactionType.DEFAULT_VALIDITY_PERIOD, eid, new Holder<String>(relatesTo));
            }
            if (response != null)

                return response;
        } catch (WSUtils.SuppressClientWSRequest s) {
            return null;
        } catch (Exception ex) {
            Utils.lg.severe("Failed to issue  getEIS  call: " + ex.getMessage());
        }
        return null;
    }

    public static void sendDownloadProfileResponse(EntityManager em,
                                                   BaseResponseType.ExecutionStatus status,
                                                   WsaEndPointReference sendTo, String originallyTo,
                                                   Long requestorId,
                                                   byte[] response, String relatesTO,
                                                   Date startDate,
                                                   String iccid) {
        if (status == null) {
            status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                    new BaseResponseType.ExecutionStatus.StatusCode("8.4", "", "4.2", ""));
        }

        Date endDate = Calendar.getInstance().getTime(); // Set it

        final RpaEntity originalRequestor = em.find(RpaEntity.class, requestorId);
        final WsaEndPointReference sender = new WsaEndPointReference(originallyTo,originalRequestor);
        final Holder<String> msgType = new Holder<String>("http://gsma" +
                ".com/ES2/ProfileManagentCallBack/ES2-DownloadProfile");
        try {
            String resp = response !=
                    null ?
                    Utils.HEX.b2H(response) : null;

                ES2 proxy = WSUtils.getPort("http://namespaces.gsma.org/esim-messaging/1", "ES2Port", sendTo, ES2.class, RpaEntity.Type.SMDP, em, requestorId);
                proxy.downloadProfileResponse(sender, sendTo.address, relatesTO, msgType, Utils.gregorianCalendarFromDate(startDate), Utils.gregorianCalendarFromDate(endDate), TransactionType.DEFAULT_VALIDITY_PERIOD, status, iccid, resp);

        } catch (WSUtils.SuppressClientWSRequest s) {
        } catch (Exception ex) {
            Utils.lg.severe("Failed to issue async downloadProfile response call: " + ex.getMessage());
        }
    }

    public static void sendEnableProfileResponse(EntityManager em,
                                                 BaseResponseType.ExecutionStatus status,
                                                 WsaEndPointReference sendTo, Long requestingEntityId, String originallyTo,
                                                 String relatesTO,
                                                 Date startDate) {
        if (status == null) {
            status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                    new BaseResponseType.ExecutionStatus.StatusCode("8.4", "", "4.2", ""));
        }

        Date endDate = Calendar.getInstance().getTime(); // Set it

        ES2 proxy = WSUtils.getPort("http://namespaces.gsma.org/esim-messaging/1", "ES2Port", sendTo, ES2.class,
                RpaEntity.Type.SMDP, em,requestingEntityId);
        final RpaEntity originalRequestor = em.find(RpaEntity.class, requestingEntityId);
        final WsaEndPointReference sender = new WsaEndPointReference(originallyTo,originalRequestor);
        final Holder<String> msgType = new Holder<String>("http://gsma" +
                ".com/ES3/ProfileManagentCallBack/ES2-EnableProfile");
        try {

            proxy.enableProfileResponse(sender, sendTo.address, relatesTO, msgType,
                    Utils.gregorianCalendarFromDate(startDate), Utils.gregorianCalendarFromDate(endDate),
                    TransactionType.DEFAULT_VALIDITY_PERIOD,
                    status);
        } catch (WSUtils.SuppressClientWSRequest s) {
        } catch (Exception ex) {
            Utils.lg.severe("Failed to issue async enableProfile response call: " + ex.getMessage());
        }
    }

    public static void sendDisableProfileResponse(EntityManager em,
                                                  BaseResponseType.ExecutionStatus status,
                                                  WsaEndPointReference sendTo, Long requestingEntityId, String originallyTo,
                                                  String relatesTO,
                                                  Date startDate) {
        if (status == null) {
            status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                    new BaseResponseType.ExecutionStatus.StatusCode("8.4", "", "4.2", ""));
        }

        Date endDate = Calendar.getInstance().getTime(); // Set it

        ES2 proxy = WSUtils.getPort("http://namespaces.gsma.org/esim-messaging/1", "ES2Port", sendTo, ES2.class,
                RpaEntity.Type.SMDP, em,requestingEntityId);
        final RpaEntity originalRequestor = em.find(RpaEntity.class, requestingEntityId);
        final WsaEndPointReference sender = new WsaEndPointReference(originallyTo,originalRequestor);
        final Holder<String> msgType = new Holder<String>("http://gsma" +
                ".com/ES3/ProfileManagentCallBack/ES2-DisableProfile");
        try {

            proxy.disableProfileResponse(sender, sendTo.address, relatesTO, msgType,
                    Utils.gregorianCalendarFromDate(startDate), Utils.gregorianCalendarFromDate(endDate),
                    TransactionType.DEFAULT_VALIDITY_PERIOD,
                    status);
        } catch (WSUtils.SuppressClientWSRequest s) {
        } catch (Exception ex) {
            Utils.lg.severe("Failed to issue async disableProfile response call: " + ex.getMessage());
        }
    }

    public static void sendDeleteProfileResponse(EntityManager em,
                                                 BaseResponseType.ExecutionStatus status,
                                                 WsaEndPointReference sendTo, Long originalRequestorId,
                                                 String originallyTo,
                                                 String relatesTO,
                                                 Date startDate) {
        if (status == null) {
            status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                    new BaseResponseType.ExecutionStatus.StatusCode("8.4", "", "4.2", ""));
        }

        Date endDate = Calendar.getInstance().getTime(); // Set it

        ES2 proxy = WSUtils.getPort("http://namespaces.gsma.org/esim-messaging/1", "ES2Port", sendTo, ES2.class,
                RpaEntity.Type.SMDP, em,originalRequestorId);
       final RpaEntity originalRequestor = em.find(RpaEntity.class, originalRequestorId);

        final WsaEndPointReference sender = new WsaEndPointReference(originallyTo,originalRequestor);
        final Holder<String> msgType = new Holder<String>("http://gsma" +
                ".com/ES3/ProfileManagentCallBack/ES2-DeleteProfile");
        try {

            proxy.deleteProfilePResponse(sender, sendTo.address, relatesTO, msgType,
                    Utils.gregorianCalendarFromDate(startDate), Utils.gregorianCalendarFromDate(endDate),
                    TransactionType.DEFAULT_VALIDITY_PERIOD,
                    status);
        } catch (WSUtils.SuppressClientWSRequest s) {
        } catch (Exception ex) {
            Utils.lg.severe("Failed to issue async deleteProfile response call: " + ex.getMessage());
        }
    }

    public static Eis getEIS(PersistenceUtility po, final RpaEntity smsr, final String eid) {
        try {
            return po.doTransaction((po1, em) -> getEIS(em, smsr, UUID.randomUUID().toString(), eid).eis);
        } catch (Exception ex) {
        }
        return null;
    }

}
