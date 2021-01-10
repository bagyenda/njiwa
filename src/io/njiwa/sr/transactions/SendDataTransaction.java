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
import io.njiwa.common.ws.types.BaseResponseType;
import io.njiwa.common.ws.types.WsaEndPointReference;
import io.njiwa.dp.ws.CommonImpl;
import io.njiwa.sr.model.Eis;
import io.njiwa.sr.ota.Ota;
import io.njiwa.sr.ws.interfaces.ES3;

import javax.ejb.Asynchronous;
import javax.persistence.EntityManager;
import javax.xml.ws.Holder;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static io.njiwa.common.SDCommand.C_APDU_TAG;

/**
 * Created by bagyenda on 09/05/2017.
 */
public class SendDataTransaction extends SmSrBaseTransaction {

    public Map<String, Boolean> respMap = new HashMap<String, Boolean>();
    public byte[] response = new byte[0];

    @Override
    public Ota.ScriptChaining commandChainingType(Ota.Params params,  Boolean moreToFollow) {
        // Annex K of SGP.02 v4.2
        Eis eis = params.eis;
        boolean active = Utils.toBool(eis.getScriptChainingActive());
        boolean useChaining = false;
        boolean more = Utils.toBool(moreToFollow);

        if (!more)  // As per Annex K, indicate there is no more scripting chaining to be done, and upper layer must mark accordingly.
            return active ? Ota.ScriptChaining.LAST_SCRIPT : Ota.ScriptChaining.NOCHAINING;

        try {
            // Case 1, last command is the first STORE DATA for a key establishment
            byte[] cmd = cAPDUs.get(cAPDUs.size() - 1);

            Utils.Pair<Integer, byte[]> x = Utils.BER.decodeTLV(cmd);
            int tag = x.k;
            if (tag != C_APDU_TAG) throw new Exception("Not a CAPDU");
            byte[] apdu = x.l;
            int cla = apdu[0] & 0xFF;
            int ins = apdu[1] & 0xFF;
            int p1 = apdu[2] & 0xFF;
            useChaining =
                    (ins == 0xE2 && p1 == 0x09) && ((cla >= 0x80 && cla <= 0x8F) || (cla >= 0xC0 && cla <= 0xCF) || (cla >= 0xE0 && cla <= 0xEF));
        } catch (Exception ex) {

        }

        // Case 2, SCP03t session init, or download template TLVs, as per Sec 4.1.3.2 SGP.02 v4.2
        if (!useChaining)
            try {
                byte[] cmd = cAPDUs.get(0);
                Utils.Pair<Integer, byte[]> x = Utils.BER.decodeTLV(cmd);
                int tag = x.k;
                if (tag == 0x84 || tag == 0x85)
                    useChaining = true;
                else if (tag == 0x86)
                    useChaining = this.index < this.cAPDUs.size() -1; // We are not at last command
            } catch (Exception ex) {}

        if (useChaining)
            return active ? Ota.ScriptChaining.SUBSEQUENT_SCRIPT_MORE_TO_FOLLOW : Ota.ScriptChaining.FIRST_SCRIPT_KEEP_ON_RESET;
        else
            return active ? Ota.ScriptChaining.LAST_SCRIPT : Ota.ScriptChaining.NOCHAINING;
    }

    @Asynchronous // XXX right?
    private void sendResponse(EntityManager em, boolean success) {
        if (status == null) {
            status = new BaseResponseType.ExecutionStatus(success ?
                    BaseResponseType.ExecutionStatus.Status.ExecutedSuccess :
                    BaseResponseType.ExecutionStatus.Status.Failed, new BaseResponseType.ExecutionStatus.StatusCode(
                            "8.1.1", "SendData", "", ""));
        } else status.status = BaseResponseType.ExecutionStatus.Status.Failed;
        Date endDate = Calendar.getInstance().getTime(); // Set it


        final WsaEndPointReference sender = new WsaEndPointReference();
        sender.address = originallyTo;
        final Holder<String> msgType = new Holder<String>("http://gsma" + ".com/ES3/ProfileManagentCallBack/ES3" +
                "-SendData");

        try {
            if (requestingEntityId == RpaEntity.LOCAL_ENTITY_ID) {
                CommonImpl.sendDataResponseHandler(em, status, relatesTO, response != null ? Utils.HEX.b2H(response)
                        : null);
            } else {
                ES3 proxy = WSUtils.getPort("http://namespaces.gsma.org/esim-messaging/1", "ES3Port",
                        getReplyToAddress(em, "ES3"), ES3.class, RpaEntity.Type.SMSR, em, requestingEntityId);
                proxy.sendDataResponse(sender, getReplyToAddress(em, "ES3").address, relatesTO, msgType,
                        Utils.gregorianCalendarFromDate(startDate), Utils.gregorianCalendarFromDate(endDate),
                        TransactionType.DEFAULT_VALIDITY_PERIOD, status, response != null ? Utils.HEX.b2H(response) :
                                null);
            }
        } catch (WSUtils.SuppressClientWSRequest wsa) {
        } catch (Exception ex) {
            Utils.lg.severe("Async sendDataResponse failed: " + ex.getMessage());
        }

    }

    @Override
    public synchronized void processResponse(EntityManager em, long tid, ResponseType rtype, String reqId) {
        Ota.ResponseHandler.ETSI102226APDUResponses r = getResponses();
        byte[] resp = r.respData; // Get entire built data, return it.
        if (rtype == ResponseType.SUCCESS) {
            // Get stuff
            if (reqId == null) reqId = "";
            // Check if we have seen this reqId before
            if (respMap.get(reqId) != null) return;
            respMap.put(reqId, true);
            // Add data to output
            int len = resp == null ? 0 : resp.length;
            int oldlen = this.response.length;
            byte[] x = new byte[len + oldlen];
            System.arraycopy(this.response, 0, x, 0, oldlen);
            System.arraycopy(resp, 0, x, oldlen, resp.length);
            this.response = x;

            if (hasMore()) return; // Still more data expected
        }
        sendResponse(em, rtype == ResponseType.SUCCESS); // Send to caller
    }


}
