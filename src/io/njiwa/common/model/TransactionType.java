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

package io.njiwa.common.model;

import io.njiwa.common.PersistenceUtility;
import io.njiwa.common.SDCommand;
import io.njiwa.common.Utils;
import io.njiwa.sr.ota.Ota;


import javax.ejb.Asynchronous;
import javax.persistence.EntityManager;
import java.util.ArrayList;
import java.util.List;

/**
 * @brief A transaction object representation
 */
public abstract class TransactionType {
    public static final int DEFAULT_VALIDITY_PERIOD = 300;
    public List<byte[]> cAPDUs; //!< List of C_APDUs as per ETSI TS 102 226. Note that according to SGP spec, this is
    // what we are passed. APDUs or SCP03t objects, wrapped inside APDUs. Also see definition of "SCP80_PACKET" in
    // SGP11 v3.1 test spec
    public int index = 0; //!< Where we are in apdu list. Outsiders can manipulate this
    public int lastIndex = 0; //!< where we stopped last in apdu list
    // *** End SM-SR stuff **
    public Long requestingEntityId; //!< The requesting RPA entity

    private Ota.ResponseHandler.ETSI102226APDUResponses responses;

    public void setResponses(Ota.ResponseHandler.ETSI102226APDUResponses responses)
    {
        this.responses = responses;
    }

    public Ota.ResponseHandler.ETSI102226APDUResponses getResponses()
    {
        return responses;
    }

    public TransactionType() {
    }

    public void addAPDU(SDCommand c) {
        if (cAPDUs == null)
            cAPDUs = new ArrayList<>();
        try {
            cAPDUs.add(c.toByteArray());
        } catch (Exception ex) {
        }
    }

    @Asynchronous // XXX right?
    protected synchronized void processResponse(EntityManager em, long tid, ResponseType status, String reqId,
                                                byte[] response) {
        // To be overridden by sub-classes
    }

    public synchronized final boolean handleResponse(PersistenceUtility po, final long tid, final ResponseType status,
                                                     final String
                                                             reqId,
                                                     final String response)
            throws Exception {
        return handleResponse(po, tid, status, reqId, response != null ? Utils.HEX.h2b(response) : null);
    }

    public synchronized final boolean handleResponse(PersistenceUtility po, final long tid, final ResponseType status,
                                                     final String
                                                             reqId,
                                                     final byte[] response) {
        return po.doTransaction((po1, em) -> handleResponse(em, tid, status, reqId, response));
    }

    /**
     * @param tid
     * @param status
     * @param response
     * @return whether there is more data to be sent
     * @brief Process the response received, e.g. send it over to the end-point. It will be called asynchronously.
     * But only one thread can be inside this at any time.
     */

    public synchronized final boolean handleResponse(EntityManager em, long tid, ResponseType status, String reqId, byte[] response) {
        try {
            if (status == ResponseType.SUCCESS)
                index = lastIndex;
            processResponse(em, tid, status, reqId, response);
        } catch (Exception ex) {
        }
        return hasMore();
    }

    public boolean handleResponse(EntityManager em, long tid, ResponseType status, String reqId, String response)
    {
        return handleResponse(em,tid,status,reqId,response != null ? Utils.HEX.h2b(response) : null);
    }

    public boolean hasMore() {
        return index < cAPDUs.size();
    }

    public final int estimateLargestPacket() {
        try {

            int l = 0;
            for (byte[] b : cAPDUs)
                if (b.length > l)
                    l = b.length;
            return l;
        } catch (Exception ex) {

        }
        return 0;
    }

    /**
     * @param em - Entity Manager
     * @param tr - Current transaction
     * @return true if transaction sent. Note that once this returns true, since we have no retry, sender should put
     * sendDate into the future and wait for response or expiry.
     * @throws Exception
     * @brief Called to send the data for the current transaction. Used by SM-DP processor
     */
    public Object sendTransaction(EntityManager em, Object tr) throws Exception {
        throw new UnsupportedOperationException();
    }

    public enum ResponseType {PROCESSING_FAILED, SUCCESS, ERROR, EXPIRED}
}
