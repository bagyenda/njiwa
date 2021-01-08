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

package io.njiwa.sr.transactions;

import io.njiwa.common.Utils;
import io.njiwa.common.model.RpaEntity;
import io.njiwa.common.model.TransactionType;
import io.njiwa.common.ws.WSUtils;
import io.njiwa.common.SDCommand;
import io.njiwa.common.ws.types.BaseResponseType;
import io.njiwa.common.ws.types.WsaEndPointReference;
import io.njiwa.sr.ota.Ota;
import io.njiwa.sr.ws.interfaces.ES3;

import javax.ejb.Asynchronous;
import javax.persistence.EntityManager;
import javax.xml.ws.Holder;
import java.io.ByteArrayOutputStream;
import java.util.Calendar;
import java.util.Date;

/**
 * Created by bagyenda on 09/05/2017.
 */
public class UpdateConnectivityParamsTransaction extends SmSrBaseTransaction {

    public UpdateConnectivityParamsTransaction() {

    }

    public UpdateConnectivityParamsTransaction(final String params) throws Exception {

        final byte[] xparams = Utils.HEX.h2b(params);
        ByteArrayOutputStream data = new ByteArrayOutputStream() {
            {
              Utils.BER.appendTLV(this, new byte[]{(byte) 0x3A, 0x07}, // Sec 4.1.3.4
                xparams);
            }
        };
        addAPDU(new SDCommand.APDU(0x80, 0xE2, 0x88, 0x00, data.toByteArray()));
    }

    @Asynchronous
    @Override
    public synchronized void processResponse(EntityManager em, long tid, ResponseType rtype, String reqId) {

        if (status == null) {
            status = new BaseResponseType.ExecutionStatus(rtype == ResponseType.SUCCESS ? BaseResponseType.ExecutionStatus.Status
                    .ExecutedSuccess : BaseResponseType.ExecutionStatus.Status.Failed,
                    new BaseResponseType.ExecutionStatus.StatusCode("8.4", "UpdateConnectivityParameters", "4.2",
                            ""));
        } else
            status.status = BaseResponseType.ExecutionStatus.Status.Failed;
        Date endDate = Calendar.getInstance().getTime(); // Set it


        final ES3 proxy = WSUtils.getPort("http://namespaces.gsma.org/esim-messaging/1", "ES3Port",
                getReplyToAddress(em, "ES3"), ES3.class, RpaEntity.Type.SMSR, em,requestingEntityId);
        // Make params to send
        final WsaEndPointReference sender = new WsaEndPointReference();
        sender.address = originallyTo;
        final Holder<String> msgType = new Holder<String>("http://gsma" +
                ".com/ES3/ProfileManagentCallBack/ES3-UpdateConnectivityParameters");

        try {
            Ota.ResponseHandler.ETSI102226APDUResponses r = getResponses();
            proxy.updateConnectivityParametersResponse(sender, getReplyToAddress(em, "ES3").address, relatesTO,
                    msgType,
                    Utils.gregorianCalendarFromDate(startDate),
                    Utils.gregorianCalendarFromDate(endDate), TransactionType.DEFAULT_VALIDITY_PERIOD, status,
                    r!= null && r.respData !=
                            null ?
                            Utils.HEX.b2H(r.respData) : null);

        } catch (WSUtils.SuppressClientWSRequest wsa) {
        } catch (Exception ex) {
            Utils.lg.severe("Failed to issue async createisdp.response call: " + ex.getMessage());
        }
    }
}
