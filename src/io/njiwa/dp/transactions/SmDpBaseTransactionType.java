package io.njiwa.dp.transactions;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.njiwa.common.Utils;
import io.njiwa.common.model.RpaEntity;
import io.njiwa.common.ws.WSUtils;
import io.njiwa.common.ws.types.BaseTransactionType;
import io.njiwa.common.ws.types.WsaEndPointReference;
import io.njiwa.sr.ws.interfaces.ES3;

import javax.persistence.EntityManager;

public class SmDpBaseTransactionType extends BaseTransactionType {
    public String iccid; // the ICCID of the profile...
    public long smsrId; // The ID of the SM-SR
    public boolean sent = false;
    @JsonIgnore
    protected RpaEntity senderRpa = null;
    @JsonIgnore
    protected RpaEntity targetSMSR = null;
    public  Utils.Triple<String, ES3, WsaEndPointReference> getES3Interface(EntityManager em)
    {
        if (targetSMSR == null)
            targetSMSR = smsrId == RpaEntity.LOCAL_ENTITY_ID ? RpaEntity.getlocalSMSR() : em.find(RpaEntity.class, smsrId);

        final WsaEndPointReference rcptTo = new WsaEndPointReference(targetSMSR, "ES3");
        final String toAddress = rcptTo.makeAddress();
        final ES3 proxy = WSUtils.getPort("http://namespaces.gsma.org/esim-messaging/1", "ES3Port",
                rcptTo, ES3.class, RpaEntity.Type.SMDP, em, requestingEntityId);

        if (senderRpa == null)
            senderRpa = RpaEntity.getlocalSMDP();

        WsaEndPointReference sender = new WsaEndPointReference(senderRpa,
                "ES3");

        return new Utils.Triple<>(toAddress,proxy,sender);
    }
}
