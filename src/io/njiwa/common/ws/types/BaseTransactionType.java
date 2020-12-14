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

package io.njiwa.common.ws.types;

import io.njiwa.common.Utils;
import io.njiwa.common.model.RpaEntity;
import io.njiwa.common.model.TransactionType;

import javax.persistence.EntityManager;
import java.util.Calendar;
import java.util.Date;

/**
 * Created by bagyenda on 20/10/2016.
 * Represents a transaction type for storing in the log
 */

public class BaseTransactionType  extends TransactionType {
    public WsaEndPointReference from; // From URL
    public WsaEndPointReference replyTo; // ReplyTo Url
    public String originallyTo; // To URL
    public String relatesTO; // Original message ID
    public long validity;
    public BaseResponseType.ExecutionStatus status = null; // The status code. If set, use it, else infer from
    // response data

    public BaseTransactionType() {} // So things work fine...
    public RpaEntity.Type requestorType;
    public Date startDate = Calendar.getInstance().getTime(); // Set it to time of creation
    public Date  endDate  = null;

    public final void updateBaseData(WsaEndPointReference from, String to, String relatesTO, long validity,
                                     WsaEndPointReference replyTo, Long requestingEntity)
    {
        this.from = from;
        this.originallyTo = to;
        this.relatesTO = relatesTO;
        this.validity = validity;
        this.replyTo = replyTo;
        this.requestingEntityId = requestingEntity;
    }

    /**
     * @brief Get the address to send to. First try the replyTo. Then the From. Then the address of the sender entity
     * @param em
     * @param interf
     * @return
     */
    public final WsaEndPointReference getReplyToAddress(EntityManager em, String interf)
    {
        WsaEndPointReference x =  (replyTo != null) ? replyTo : from;
        if (x == null && requestingEntityId != null) try {
            RpaEntity rpa = em.find(RpaEntity.class,requestingEntityId);
            String url = rpa.urlForInterface(interf);
            if (url == null)
                return null;
            x = new WsaEndPointReference(url);
        } catch (Exception ex) {

        }
        return x;
    }

    /**
     * @brief marks transaction as complete by setting end time, cleans up status field
     * @param em
     * @return
     */
    public  Utils.Pair<WsaEndPointReference,WsaEndPointReference> markTransactionEnded(EntityManager em)
    {
        endDate = Calendar.getInstance().getTime();
        if (status == null)
            status = new BaseResponseType.ExecutionStatus(BaseResponseType.ExecutionStatus.Status.Failed,
                    new BaseResponseType.ExecutionStatus.StatusCode("8.4", "", "4.2", ""));
        WsaEndPointReference
                replyToAddress = getReplyToAddress(em, requestorType == RpaEntity.Type.SMDP ? "ES3" : "ES4");
        final WsaEndPointReference sender = new WsaEndPointReference();
        sender.address = originallyTo;

        return  new Utils.Pair<>(replyToAddress,sender);
    }

}
