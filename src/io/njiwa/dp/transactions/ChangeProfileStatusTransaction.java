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

package io.njiwa.dp.transactions;

import io.njiwa.common.Utils;
import io.njiwa.common.model.RpaEntity;
import io.njiwa.common.ws.WSUtils;
import io.njiwa.common.ws.types.WsaEndPointReference;
import io.njiwa.dp.model.Euicc;
import io.njiwa.dp.model.SmDpTransaction;
import io.njiwa.dp.ws.ES2Client;
import io.njiwa.common.ws.types.BaseResponseType;
import io.njiwa.sr.ws.CommonImpl;
import io.njiwa.sr.ws.interfaces.ES3;

import javax.persistence.EntityManager;
import javax.xml.ws.Holder;
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;

/**
 * Created by bagyenda on 09/05/2017.
 */
public class ChangeProfileStatusTransaction extends SmDpBaseTransactionType {
    public Action action;

    public ChangeProfileStatusTransaction() {
    }

    public ChangeProfileStatusTransaction(long smsrId, Action action, String iccid) {
        this.action = action;
        this.smsrId = smsrId;
        this.iccid = iccid;
        sent = false;
    }

    @Override
    public Object sendTransaction(EntityManager em, Object tr) throws Exception {
        final SmDpTransaction trans = (SmDpTransaction) tr; // Grab the transaction
        final String eid = em.find(Euicc.class, trans.getEuicc()).getEid();
        String msgID = trans.newRequestMessageID(); // Create new one.
        final BaseResponseType.ExecutionStatus status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.ExecutedSuccess, new BaseResponseType.ExecutionStatus.StatusCode("8" +
                ".1.1", "", "", ""));
        long trId;
        // Send as is. Get proxy, do the thing.
        try {
            Utils.Triple<String, ES3, WsaEndPointReference> es3 = getES3Interface(em);
            final ES3 proxy = es3.l;
            final String toAddress  = es3.k;
            WsaEndPointReference sender = es3.m;


            Holder<String> msgType;
            switch (action) {
                case ENABLE:
                    msgType = new Holder<>("http://gsma" + ".com/ES3/ProfileManagement/ES3-EnableProfile");
                    if (smsrId == RpaEntity.LOCAL_ENTITY_ID)
                        trId = CommonImpl.enableProfile(em,senderRpa,eid,status,iccid,
                                sender,"",msgID,DEFAULT_VALIDITY_PERIOD,null,msgType);
                    else
                        proxy.enableProfile(sender, toAddress, null, msgID, msgType, msgID, DEFAULT_VALIDITY_PERIOD, eid, iccid, null);

                    break;
                case DISABLE:
                    msgType = new Holder<>("http://gsma" +
                            ".com/ES3/ProfileManagement/ES3-DisableProfile");
                    if (smsrId == RpaEntity.LOCAL_ENTITY_ID)
                        trId = CommonImpl.disableProfile(em,senderRpa,eid,status,iccid,sender,toAddress,msgID,DEFAULT_VALIDITY_PERIOD,null,msgType);
                    else
                        proxy.disableProfile(sender, toAddress, null, msgID, msgType, msgID, DEFAULT_VALIDITY_PERIOD,
                                eid, iccid, null);
                    break;
                case DELETE:
                    msgType = new Holder<>("http://gsma" +
                            ".com/ES3/ProfileManagement/ES3-DeleteISDP");
                    if (smsrId == RpaEntity.LOCAL_ENTITY_ID)
                        trId = CommonImpl.deleteProfile(em,senderRpa,eid,status,iccid,sender,toAddress,msgID,DEFAULT_VALIDITY_PERIOD,null,msgType);
                    else
                        proxy.deleteISDP(sender, toAddress, null, msgID, msgType, msgID, DEFAULT_VALIDITY_PERIOD,
                            eid, iccid, null);
                    break;
            }
            sent = true;
        } catch (WSUtils.SuppressClientWSRequest wsa) {
            sent = false;
        } catch (Exception ex) {

            return false;
        }

        return true;
    }

    @Override
    protected synchronized void processResponse(EntityManager em, long tid, ResponseType responseType, String reqId,
                                                byte[] response) {
        // response encodes the execution status. So, get it back
        try {
            ObjectInputStream bin = new ObjectInputStream(new ByteArrayInputStream(response));
            BaseResponseType.ExecutionStatus executionStatus = (BaseResponseType.ExecutionStatus) bin.readObject();

            switch (action) {
                case DISABLE:
                    ES2Client.sendDisableProfileResponse(em, executionStatus,
                            getReplyToAddress(em, "ES2"),
                            requestingEntityId, originallyTo, relatesTO, startDate);
                    break;
                case ENABLE:
                    ES2Client.sendEnableProfileResponse(em, executionStatus, getReplyToAddress(em, "ES2"),
                            requestingEntityId,originallyTo, relatesTO, startDate);
                    break;
                case DELETE:
                    ES2Client.sendDeleteProfileResponse(em, executionStatus, getReplyToAddress(em, "ES2"),
                            requestingEntityId,originallyTo, relatesTO, startDate);
                    break;
            }
            // XX We shouldn't care about the local copy of the ISDP. Right??
        } catch (Exception ex) {
        }
    }

    @Override
    public boolean hasMore() {
        return !sent;
    }

    public enum Action {ENABLE, DISABLE, DELETE}
}
