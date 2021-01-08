package io.njiwa.dp.ws;

import io.njiwa.common.SDCommand;
import io.njiwa.common.Utils;
import io.njiwa.common.model.TransactionType;
import io.njiwa.common.ws.WSUtils;
import io.njiwa.common.ws.types.BaseResponseType;
import io.njiwa.dp.model.ISDP;
import io.njiwa.dp.model.SmDpTransaction;
import io.njiwa.dp.transactions.ChangeProfileStatusTransaction;
import io.njiwa.dp.transactions.DownloadProfileTransaction;
import io.njiwa.dp.transactions.SmDpBaseTransactionType;

import javax.persistence.EntityManager;
import javax.ws.rs.core.Response;

/**
 * @brief Common functions
 */
public class CommonImpl {

    public static void createISDPResponseHandler(EntityManager em,
                                          String aid,
                                          String messageId,
                                          boolean isSuccess,
                                          String data) {
         SmDpTransaction tr = SmDpTransaction.findbyRequestID(em, messageId);
        // Get the object
         DownloadProfileTransaction trObj = (DownloadProfileTransaction)tr.transactionObject();
        byte[] resp;
        try {
            resp = Utils.HEX.h2b(data);
        } catch (Exception ex) {
            resp = null;
            isSuccess = false;
        }

        Utils.lg.info( String.format("Received createISDPresponse [%s] from [%s], eid [%s]", data,aid, tr != null ? tr.getEuicc() : 0));
        final TransactionType.ResponseType responseType = isSuccess ? TransactionType.ResponseType.SUCCESS :
                TransactionType.ResponseType.ERROR;
        trObj.handleResponse(em, tr.getId(), responseType, messageId, data);
        ISDP isdp;
        try {
            isdp = tr.getIsdp();
        } catch (Exception ex) {
            isdp = null;
        }
        try {
            if (isSuccess) {
                isdp.setAid(aid); // Update AID from server
                isdp.setState(ISDP.State.Created); // Move to next status
            } else if (isdp != null) {
                try {
                    tr.setIsdp(null);
                    em.remove(tr.getIsdp());
                } catch (Exception ex) {
                }
                // Reply to MNO...
            }
        } catch (Exception ex) {

        }
    }

    public static void sendDataResponseHandler(EntityManager em,
                                               BaseResponseType.ExecutionStatus executionStatus,
                                               String messageId, String data)
    {
        final SmDpTransaction tr = SmDpTransaction.findbyRequestID(em, messageId);
        // Get the object
        final DownloadProfileTransaction trObj = (DownloadProfileTransaction)tr.transactionObject();


        final TransactionType.ResponseType responseType = executionStatus.status == BaseResponseType.ExecutionStatus.Status.ExecutedSuccess ? TransactionType.ResponseType
                .SUCCESS :
                TransactionType.ResponseType.ERROR;
        trObj.handleResponse(em, tr.getId(), responseType, messageId, data);
    }

    public static void ISDPstatusChangeresponseHandler(EntityManager em, String messageId,
                                                       ChangeProfileStatusTransaction.Action action,
                                                       BaseResponseType.ExecutionStatus executionStatus,
                                                       String data)
    {
        final SmDpTransaction tr = SmDpTransaction.findbyRequestID(em, messageId);
        // Get the object
        final SmDpBaseTransactionType trObj =  (SmDpBaseTransactionType)tr.transactionObject();


        final TransactionType.ResponseType responseType = executionStatus.status == BaseResponseType.ExecutionStatus.Status.ExecutedSuccess ? TransactionType.ResponseType
                .SUCCESS :
                TransactionType.ResponseType.ERROR;
        tr.recordResponse(em, "EnableProfile", data, responseType == TransactionType.ResponseType.SUCCESS); // Record response type
        trObj.handleResponse(em, tr.getId(), responseType, messageId, data);
    }


}
