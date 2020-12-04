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

package io.njiwa.sr;

import io.njiwa.common.model.TransactionType;
import io.njiwa.common.GenericPeriodicProcessor;
import io.njiwa.common.ServerSettings;
import io.njiwa.common.Utils;
import io.njiwa.sr.model.Eis;
import io.njiwa.sr.model.SmSrTransaction;
import io.njiwa.sr.model.SmSrTransactionRequestId;
import io.njiwa.sr.transactions.SmSrBaseTransaction;
import io.njiwa.sr.transports.BipCatTP;
import io.njiwa.sr.transports.RamHttp;
import io.njiwa.sr.transports.Sms;
import io.njiwa.sr.transports.Transport;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.annotation.Resource;
import javax.ejb.*;
import javax.enterprise.concurrent.ManagedExecutorService;
import javax.inject.Inject;
import javax.persistence.EntityManager;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Created by bagyenda on 28/09/2016.
 */
@Singleton
@Startup
@DependsOn({"Sms", "Bip", "RamHTTP"})
@ConcurrencyManagement(ConcurrencyManagementType.BEAN)
public class SmSrTransactionsPeriodicProcessor extends GenericPeriodicProcessor<SmSrTransaction> {

    @Resource
    private ManagedExecutorService xtaskExecutor; //!< Managed thread runner so we don't have to make new threads
    // ourselves

    private static final String query = "SELECT id from SmSrTransaction WHERE nextSend < current_timestamp AND status " +
            "in (:r, :i, :s, :b,:t)";
    private static final Map<String, Object> params = new ConcurrentHashMap<String, Object>() {{
        put("r", SmSrTransaction.Status.Ready);
        put("i", SmSrTransaction.Status.InProgress);
        put("b", SmSrTransaction.Status.BipWait);
        put("s", SmSrTransaction.Status.Sent);
        put("t", SmSrTransaction.Status.HttpWait);
    }};

    // The transports. Dynamically injected. Right?
    private static Sms sms = null;  //!< Link to SMS transport
    private static BipCatTP bipCatTP = null;  //!< Link to BIP transport
    private static RamHttp ramHttp = null; //!< Link to SCWS transport

    public static ManagedExecutorService taskExecutor; // Oh what a terrible kludge!
    @Inject
    BipCatTP xbip;

    @Inject
    private Sms xsms;

    @Inject
    private RamHttp xramhttp;

    // The generic processor handler

    @PostConstruct
    public void doStart() {
        Utils.lg.info(String.format("Starting SM-SR Transaction Log Processor..."));
        sms = xsms;
        bipCatTP = xbip;
        ramHttp = xramhttp;
        taskExecutor = xtaskExecutor; // Terrible! Terrible! Kludge
        start(true, "transactionLog", query, params);
    }

    @PreDestroy
    public void doStop() {
        try {
            super.stop();
        } catch (Exception ex) {
        }

        try {
            sms.stop();

        } catch (Exception ex) {
        }

        try {
            bipCatTP.stop();
        } catch (Exception ex) {
        }

        try {
            ramHttp.stop();
        } catch (Exception ex) {

        }
        stop();
        Utils.lg.info(String.format("Stopped Transaction Log Processor."));
    }

    public static Object sendTrans(EntityManager em, SmSrTransaction t) {
        // Implement sending a transaction

        try {
            SmSrTransaction.Status status = t.getStatus();
            if (status != SmSrTransaction.Status.BipWait &&
                    status != SmSrTransaction.Status.HttpWait &&
                    status != SmSrTransaction.Status.Ready &&
                    status != SmSrTransaction.Status.InProgress &&
                    status != SmSrTransaction.Status.Sent) {
                Utils.lg.info(String.format("Transaction [%d] is not active, skipping it", t.getId()));
                t.setNextSend(Utils.infiniteDate);
                em.flush();
                return null;
            }
            SmSrBaseTransaction transObject = (SmSrBaseTransaction) t.getTransObject();
            int maxRetries = ServerSettings.getMaxRetries();
            int retryInterval = ServerSettings.getRetryInterval();
            int retries = t.getRetries();
            Date expiryDate = t.getExpires();
            Date tnow = Calendar.getInstance().getTime();

            if (retries > maxRetries || tnow.after(expiryDate)) {
                // Go away
                t.failTransaction(em, SmSrTransaction.Status.Expired);
                transObject.handleResponse(em, t.getId(), TransactionType.ResponseType.EXPIRED, "",
                        new
                                byte[0]);
                return true;
            }

            long tnowSecs = tnow.getTime();
            // Now add seconds
            int xretries = retries + 1;
            long secs = ServerSettings.isGeometricBackOff() ? (retryInterval * xretries) : retryInterval;
            Date afterT = new Date(tnowSecs + secs * 1000);

            // Update it as well
            t.setNextSend(afterT);
            t.setRetries(retries + 1);
            t.setStatus(SmSrTransaction.Status.InProgress);
            em.flush(); // Push out changes. Right??

            try {
                transObject.setTransports(sms, bipCatTP, ramHttp); // Store them before we process
                Object xres = transObject.sendTransaction(em, t);
                SmSrTransaction.Status next_status;
                Transport.MessageStatus msgStatus;
                String reqId;

                if (xres instanceof Boolean) { // Boolean might be sent by other types of destinations (e.g. HTTP)
                    boolean res = (Boolean) xres;
                    next_status = res ? SmSrTransaction.Status.Sent : SmSrTransaction.Status.Failed;
                    msgStatus = res ? Transport.MessageStatus.Sent : Transport.MessageStatus.SendFailed;
                    reqId = null;
                } else if (xres instanceof Utils.Triple) {
                    Utils.Triple<Integer, Transport.MessageStatus,
                            Utils.Triple<Long, String, Transport.TransportType>> sres =
                            (Utils.Triple) xres;
                    msgStatus = sres.l;
                    next_status = SmSrTransaction.Status.fromTransStatus(msgStatus); // msgStatus.toTransStatus();
                    // int count = sres.k;
                    long nextMillisecs = sres.m.k;
                    reqId = msgStatus != Transport.MessageStatus.NotSent ? sres.m.l : null;
                    Transport.TransportType method = sres.m.m;
                    t.setLastTransportUsed(method);
                    t.setTransportMessageStatus(msgStatus);
                    if (nextMillisecs > 0)
                        t.setNextSend(new Date(tnowSecs + nextMillisecs * 1000));
                } else {
                    next_status = SmSrTransaction.Status.Ready;
                    msgStatus = Transport.MessageStatus.SendFailed;
                    reqId = null;
                }
                t.setStatus(next_status);
                t.setLastrequestID(reqId);
                t.setLastSend(new Date());
                t.setNumberOfAttempts(t.getNumberOfAttempts() + 1);
                Eis eis = t.eisEntry(em);
                String msisdn = eis.activeMISDN();
                t.setMsisdn(msisdn); // Set it. Right?
                if (reqId != null) { // Add to request IDs table
                    SmSrTransactionRequestId trid = new SmSrTransactionRequestId(reqId, t, msisdn);
                    em.persist(trid);
                }
                if (msgStatus != Transport.MessageStatus.Sent)
                    t.setRetries(t.getRetries() - 1);

                em.flush();
            } catch (Exception ex) {
                Utils.lg.severe(String.format("Error sending trans %d to [%s]: %s", t.getId(), t.getMsisdn(), ex));
            }
        } catch (Exception ex) {
            Utils.lg.severe(String.format("Error sending trans %d to [%s]: %s", t.getId(), t.getMsisdn(), ex));
        }
        return null;
    }


    @Override
    protected Object processTask(EntityManager em, SmSrTransaction t) throws Exception {
        return sendTrans(em, t);
    }

    // For afterTask, use default

}
