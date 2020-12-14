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
import io.njiwa.dp.model.Euicc;
import io.njiwa.dp.model.SmDpTransaction;
import io.njiwa.common.ws.types.WsaEndPointReference;
import io.njiwa.sr.ws.CommonImpl;
import io.njiwa.sr.ws.interfaces.ES3;
import io.njiwa.sr.ws.types.Pol2Type;

import javax.persistence.EntityManager;
import javax.xml.ws.Holder;

/**
 * Created by bagyenda on 25/05/2017.
 */
public class UpdatePolicyRulesTransaction extends SmDpBaseTransactionType {
    public Pol2Type pol2;

    public UpdatePolicyRulesTransaction() {}

    public UpdatePolicyRulesTransaction(long smsrId,String iccid, Pol2Type pol2)
    {
        this.pol2 = pol2;
        this.smsrId = smsrId;
        this.iccid = iccid;
        sent = false;
    }
    @Override
    public boolean hasMore() {
        return !sent;
    }



    @Override
    public Object sendTransaction(EntityManager em, Object tr) throws Exception {
        final SmDpTransaction trans = (SmDpTransaction) tr; // Grab the transaction
        final String eid = em.find(Euicc.class, trans.getEuicc()).getEid();
        Utils.Triple<String, ES3, WsaEndPointReference> es3 = getES3Interface(em);
        final ES3 proxy = es3.l;
        final String toAddress  = es3.k;
        WsaEndPointReference sender = es3.m;
        RpaEntity smsr = targetSMSR;
        try {

            String msgID = trans.newRequestMessageID(); // Create new one.
            Holder<String> msgType = new Holder<>("http://gsma.com/ES3/ProfileManagement/ES3-UpdatePolicyRules");
            if (smsrId == RpaEntity.LOCAL_ENTITY_ID)
                CommonImpl.updatePolicyRules(em,senderRpa,eid,iccid,pol2);
            else
                proxy.updatePolicyRules(sender,toAddress,null,msgID,msgType,msgID,DEFAULT_VALIDITY_PERIOD,eid,
                    iccid,pol2);
        } catch (WSUtils.SuppressClientWSRequest wsa) {
        } catch (Exception ex) {

            return false;
        }
        return true;
    }

}
