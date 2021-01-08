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
import io.njiwa.common.ws.types.BaseTransactionType;
import io.njiwa.sr.Session;
import io.njiwa.sr.model.Eis;
import io.njiwa.sr.model.SmSrTransaction;
import io.njiwa.sr.ota.Ota;
import io.njiwa.sr.transports.BipCatTP;
import io.njiwa.sr.transports.RamHttp;
import io.njiwa.sr.transports.Sms;
import io.njiwa.sr.transports.Transport;

import javax.persistence.EntityManager;
import java.util.List;

/**
 * Created by bagyenda on 08/05/2017.
 */
public class SmSrBaseTransaction extends BaseTransactionType {
    private Sms sms;
    private BipCatTP bipCatTP;
    private RamHttp ramHttp;


    @Override
    protected synchronized void processResponse(EntityManager em, long tid, ResponseType status, String reqId,
                                                byte[] response) {
        processResponse(em,tid,status,reqId);
    }

    protected synchronized void processResponse(EntityManager em, long tid, ResponseType status, String reqId) {
        // To be overridden by sub-classes
    }

    private Ota.ResponseHandler.ETSI102226APDUResponses responses;

    public void setResponses(Ota.ResponseHandler.ETSI102226APDUResponses responses)
    {
        this.responses = responses;
    }

    public Ota.ResponseHandler.ETSI102226APDUResponses getResponses()
    {
        return responses;
    }

    public Ota.ResponseHandler.ETSI102226APDUResponses.Response findFirstResponseByType(Ota.ResponseHandler.ETSI102226APDUResponses.Response.ResponseType type)
    {
        try {
            Ota.ResponseHandler.ETSI102226APDUResponses rl = getResponses();
            for (Ota.ResponseHandler.ETSI102226APDUResponses.Response r : rl.responses)
                if (r.type == type)
                    return  r;
        } catch (Exception ex) {

        }
        return null;
    }

    public Ota.ResponseHandler.ETSI102226APDUResponses.Response findFirstRAPDU()
    {
        return findFirstResponseByType(Ota.ResponseHandler.ETSI102226APDUResponses.Response.ResponseType.RAPDU);
    }

    public void setTransports(Sms sms, BipCatTP bipCatTP, RamHttp http) {
        this.sms = sms;
        this.bipCatTP = bipCatTP;
        this.ramHttp = http;
    }


    private static final String TAG = "TRLOG";

    @Override
    public Object sendTransaction(EntityManager em,
                                  Object xtr) throws Exception {

        SmSrTransaction tr = (SmSrTransaction) xtr;
        Eis eis = tr.eisEntry(em);
        long transid = tr.getId();
        Transport.TransportType transportType;
        Transport sender = sms;
        List<byte[]> capdus = tr.getTransObject().cAPDUs;
        int startIndex = tr.getTransObject().index;
        boolean hasMore =  tr.getMoreToFollow(); // XXX Should we not honour this flag here?
        boolean canUseSMS = sms.canUseSMS(capdus);
        // Determine transport from what it supports: For now simply try them one by one
        if (canUseSMS && !hasMore)
            transportType = Transport.TransportType.SMS;
        else if (eis.hasHttpSupport()) {
            transportType = Transport.TransportType.RAMHTTP;
            sender = ramHttp;
        } else if (eis.getCat_tp_support()) { // Always assume SCP 80 keys are present
            transportType = Transport.TransportType.BIP;
            sender = bipCatTP;
        } else
            transportType = Transport.TransportType.SMS; // Fall back. And hope for the best!

        Ota.Params otaParams = new Ota.Params(eis, tr.getTargetAID(), null);
        int largestSize = tr.getTransObject().estimateLargestPacket();
        // Get context
        Transport.Context ctx = sender.getContext(eis, otaParams, transid, largestSize);
        if (ctx == null && canUseSMS) {
            sender = sms;
            ctx = sender.getContext(eis, otaParams, transid, largestSize);
        }
        if (ctx == null)
            throw new Exception("No supported transport mechanism");
        // Make the package
        final Transport finalTransport = sender;
        final Transport.Context finalCtx = ctx;
        Utils.Pair<byte[], Integer> xres = Ota.mkOTAPkg(otaParams, capdus, startIndex,
                (l) -> finalTransport.hasEnoughBuffer(finalCtx,(int)l));
        Session gwsession = new Session(em, eis);
        String reqId = otaParams.mkRequestID();

        Utils.Triple<Integer, Long, Transport.MessageStatus> sres;
        if (xres.k != null && xres.k.length > 0)
             sres = sender.sendOTA(gwsession, otaParams, em, ctx, reqId,
                transid, transportType.toString(), TAG, xres.k);
        else {
            Utils.lg.warning(String.format("No OTA data to send, [eis: %s], tr [%s]", eis,transid));
            sres = null;
        }
        int lastIndex = xres.l;
        tr.getTransObject().lastIndex = lastIndex; // Set the last requested index
        reqId = ctx.requestID;
        ctx.destroy();

        if (sres == null)
            return null;
        int count = sres.k;
        long nextSecs = sres.l;
        Transport.MessageStatus messageStatus = sres.m;

        return new Utils.Triple<>(count, messageStatus, new Utils.Triple<>
                (nextSecs, reqId, sender.sendMethod()));
    }
}
