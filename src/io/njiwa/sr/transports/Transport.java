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

package io.njiwa.sr.transports;

import io.njiwa.common.PersistenceUtility;
import io.njiwa.common.ServerSettings;
import io.njiwa.common.Utils;
import io.njiwa.sr.Session;
import io.njiwa.sr.model.DlrTracker;
import io.njiwa.sr.model.Eis;
import io.njiwa.sr.model.SmSrTransaction;
import io.njiwa.sr.ota.Ota;


import javax.persistence.EntityManager;
import javax.persistence.LockModeType;
import java.util.Calendar;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;


/**
 *
 * @Summary This is the main transports interface/definition
  *
  * @details
 * A transport is a mechanism for delivering and receiving OTA and general (SMS) messages. Currently there are three transports:
 * SMS, BIP/CAT_TP, RAM-over-HTTP.
 *
 * A transport defines certain interfaces and methods that are used by upper levels to send messages, receive DLR,
 * receive message sending status, etc.
 */

/**
 * @brief This the main Transports definition/interface Sub-classed by  the SMS and BIP transports
 */
public abstract class Transport {
    // Represents a transport, e.g. BIP or SMS

    public enum PacketType {MO,MT};

    // These flags are from kannel.
    public static final int DLR_NONE = 0;
    public static final int DLR_DELIVERED_TO_PHONE = 1;
    public static final int DLR_NONDELIVERED_TO_PHONE = 2;
    public static final int DLR_DELIVERED_TO_SMSC = 8;
    public static final int DLR_NONDELIVERED_TO_SMSC = 16;
    public static final int DLR_ALL = (DLR_DELIVERED_TO_PHONE | DLR_NONDELIVERED_TO_PHONE | DLR_DELIVERED_TO_SMSC | DLR_NONDELIVERED_TO_SMSC);
    // It is vital that the default DLR requested inclue delivery to SMSC because we use this to track non-confirmed message (sms/push) delivery.
    public static final int DLR_REQUEST_DEFAULT = (DLR_DELIVERED_TO_PHONE | DLR_NONDELIVERED_TO_PHONE | DLR_DELIVERED_TO_SMSC);
    // public int CPI = -1;
    protected String unit = "bytes";
    boolean started = false;

    /**
     * @brief Receive a delivery report and route it to the right handler module using \e dlrHandlers
     * @param po
     * @param msisdn
     * @param dlrCode
     * @param sms_id
     * @param tag
     * @param tagID
     * @param partNo
     */
    public static void receiveDlr(PersistenceUtility po, final String msisdn,
                                  final int dlrCode,
                                  final long sms_id,
                                  final String tag,
                                  final long tagID,
                                  final int partNo) {

        // We need to get the tracker info, mark as received if it is, then call the guy who needs to be informed.

        po.doTransaction(new PersistenceUtility.Runner<Object>() {
            @Override
            public Object run(PersistenceUtility po, EntityManager em) throws Exception {
                boolean allDelivered;
                if (dlrCode == DLR_DELIVERED_TO_PHONE) {
                    try {
                        // DlrTracker tracker = em.find(DlrTracker.class, sms_id);
                        allDelivered = em.find(DlrTracker.class, sms_id, LockModeType.PESSIMISTIC_WRITE).markMessagePartDelivered(partNo);
                    } catch (Exception ex) {
                        allDelivered = false;
                    }
                } else
                    allDelivered = false;

                // Now based on the tag, route the message.

                Utils.lg.info(String.format("Received DLR [id: %s, code: %s, tag: %s, objId: %s, partNo: %s] ",
                        sms_id, dlrCode, tag, tagID, partNo
                       ));
                processDlr(po, em, msisdn, tagID, dlrCode, allDelivered);

                DlrTracker.clearOldTrackers(em); // Amortise cleanup here. Right??
                return null;
            }

            @Override
            public void cleanup(boolean success) {

            }
        });

    }



    public String getName() {
        throw new UnsupportedOperationException();
    }

    public TransportType sendMethod() {
        throw new UnsupportedOperationException();
    }

    public boolean isRunning() {
        return started;
    }

    public synchronized void start() throws Exception {
        throw new UnsupportedOperationException();
    }


    /**
     * @brief process a message status after the message has been sent (or not)
     * @param em
     * @param t
     * @param success
     * @param retry
     * @param data
     * @return True if callee should continue with normal updates, false otherwise.
     */
    public boolean processTransMessageStatus(EntityManager em, SmSrTransaction t, boolean success, boolean retry, byte[]
            data) {
        throw new UnsupportedOperationException();
    }

    /**
     * @brief After a transaction response is received and processed, this transport method is called to perform
     * any additional processing (such as sending out additional transactions, in the case of BIP)
     * @param em
     * @param t
     * @param oldstatus
     * @param oldmsgStatus
     * @return
     */
    public boolean postProcessRecvdTransaction(EntityManager em, SmSrTransaction t, SmSrTransaction.Status
            oldstatus, MessageStatus oldmsgStatus) {
        // throw new NotImplementedException();
        return true;
    }

    public void stop() throws Exception {
    }

    /**
     * @brief Send a message, return the count, next status of the transaction (whether sent or not) and the delta (in seconds) when to next try.
     * @param em - Entity Manager
     * @param context - The transport context
     * @param msg - The message to send (possibly modified by the context)
     * @param dlr_flags - DLR flags
     * @return - A triple: Number of distinct packets sent, The new message status, after how many seconds to next retry
     * @throws Exception
     */
    public Utils.Triple<Integer, MessageStatus, Long> sendMsg(EntityManager em, Context context, byte[] msg, int dlr_flags) throws Exception {
        throw new UnsupportedOperationException();
    }

    /**
     * @brief Check whether the SIM  has enough space for a message of \e dlen size using the given transport
     * For SMS this checks the on-SIM CSMS buffer size. For BIP the on-SIM BIP buffer size
     * @param ctx
     * @param dlen
     * @return
     */
    public boolean hasEnoughBuffer(Context ctx, int dlen) {

        return dlen < ctx.maxMessageSize; // By default. Right?
    }

    /**
     * @brief Return the number of 'units' in the given message size. E.g. for SMS this returns the number of CSMS
     * @param dlen
     * @return
     */
    public int unitsCount(int dlen) {
        return dlen;
    }

    /**
     * @brief This method returns a send context or null if the transport is not supported for this recipient (e.g. no BIP)
     *  It may mask out some bits in some of the Ota params. If NULL or exception, then this transport is not supported.
     */
    public Context getContext(Eis sim, Ota.Params otaParams, long transID, int pktSize) {

        throw new UnsupportedOperationException();
    }


    /**
     * @brief Modify the TEXT to send, e.g. if it should become a PUSH message for BIP
      */
    public byte[] messageToSend(EntityManager em, Context context,
                                Ota.Params params,
                                byte[] text) {
        return text;
    }

    /**
     * @brief Get the 03.48 CPI parameter, if any. -1 indicates no CPI (e.g. for SMS)
     * @param context
     * @return
     */
    public int getCPI(Context context) {
        return -1;
    } // By default, no CPI.

    /**
     * @brief Get the measurement unit for package sizes
     * @param context
     * @return
     */
    public String getUnit(Context context) {
        return unit;
    }

    /**
     * @brief Send an OTA message. Create the 03.48 package, send the message
     * @param gwSession
     * @param otaParams
     * @param em
     * @param ctx
     * @param reqId
     * @param transId
     * @param type
     * @param tag
     * @param text
     * @return the number of messages sent, when to next retry sending (if at all), the sending status
     * @throws Exception
     */
    public Utils.Triple<Integer, Long, Transport.MessageStatus> sendOTA(Session gwSession,
                                                                        Ota.Params otaParams, EntityManager em,
                                                                        Context ctx,
                                                                        String reqId,
                                                                        long transId,
                                                                        String type,
                                                                        String tag,
                                                                        byte[] text) throws Exception {
        Transport sender = this;
        // Set DLR flags
        boolean hasDlr = (otaParams.spi2 & 0x03) != 0;
        boolean smsDlr = ((otaParams.spi2 >> 5) & 0x01) != 0;
        int porDlr = (otaParams.forceDLR || (hasDlr && !smsDlr)) ? Transport.DLR_REQUEST_DEFAULT : Transport.DLR_NONE;

        Eis sim = gwSession.getEuicc();
        porDlr |= (porDlr << 8); // Keep it in higher octet as well, for later.
        if (ServerSettings.isAlwaysUseDlr())
            porDlr |= Transport.DLR_ALL;
        // Try and make the package
        byte[] pkg;

        text = sender.messageToSend(em, ctx, otaParams, text); // Mogrify message
        int cpi = sender.getCPI(ctx);
        String msisdn = sim.activeMISDN();
        Utils.lg.info(String.format("+++Packet Dump [MSISDN=%s, TAR=%s, rfmApp=%s, CPI=%s]+++%s+++",
                msisdn,
                otaParams.getTARasString(),
                otaParams.sd != null ? otaParams.sd.description() : "n/a",
                cpi >= 0 ? cpi : "n/a",
                Utils.HEX.b2H(text)));
        if (otaParams.no034bPacking)
            pkg = text;
        else {
                pkg = Ota.createSCP80Pkg(gwSession, otaParams.sd, otaParams.getTAR(), text, cpi,
                        otaParams.porOnError, // Might come from RamHTTP
                        otaParams.rfmCounter);


            if (otaParams.rfmCounter == null)
                otaParams.rfmCounter = gwSession.last_rfm_counter; // Grab it.

            if (reqId == null)
                reqId = otaParams.mkRequestID(); // Get a default.

            int pktLen = pkg.length;

            Utils.lg.info(String.format("+++OTA Dump [MSISDN=%s, TAR=%s]+++%s+++", msisdn, otaParams.getTARasString(),
                    Utils.HEX.b2H(pkg)));

            if (!sender.hasEnoughBuffer(ctx, pktLen)) {
                Utils.lg.severe(String.format("Send Transaction [%d]: Packet size [%d %s] exceeded on-SIM buffer size of" +
                                " [%d %s] sending to %s",
                        transId, sender.unitsCount(pktLen),
                        sender.getUnit(ctx),
                        ctx.maxMessageSize,
                        sender.getUnit(ctx),
                        msisdn
                ));

                return null;
            }
        }

        ctx.tag = tag; // Set the tag so DLR are tracked.
        ctx.tagId = transId;
        ctx.requestID = reqId;

        Utils.Triple<Integer, Transport.MessageStatus, Long> sres = sender.sendMsg(em, ctx, pkg, porDlr);
        Transport.MessageStatus messageStatus = sres.l;
        int count = sres.k;
        long nextSecs = sres.m;

        if (messageStatus == MessageStatus.Sent)
            Utils.lg.info(String.format("%s: Dispatched %d %s to [%s] via %s, res=%s",
                    type,
                    sender.unitsCount(count),
                    sender.getUnit(ctx),
                    msisdn,
                    sender.getName(),
                    messageStatus
            ));
        else
           Utils.lg.info(String.format("%s: Not sent, status=%s", type, messageStatus));

        return new Utils.Triple<>(count, nextSecs, messageStatus);
    }

    /**
     * @brief Call into the HLR to see if this subscriber has a data plan. Update our database record accordingly

     * @param sim
     * @return
     */
    public static boolean checkAndUpdateSimDataFlag(Eis sim, TransportType type)
    {
        boolean hasDataPlan = Utils.toBool(sim.getHasDataPlan());
        int numOpenRequests = type == TransportType.BIP ?  sim.getNumPendingBipRequests() : sim
                .getNumPendingRAMRequests(); // Only RAM or
        // BIP for now. Right?
        String[] a = Utils.execCommand(ServerSettings.getHlr_gateway_command(), new String[]{sim.activeMISDN()}, new String[]
                {"1"}); // Default to YES
        String res = a[0];
        int x = Integer.parseInt(res);
        if (x >= 0) {
            hasDataPlan = x != 0; // We got it. So, do the needful
            // Update the sim
            sim.setHasDataPlan(hasDataPlan);
            if (type == TransportType.BIP) {

                if (numOpenRequests >= ServerSettings.getMax_bip_send_requests())
                    sim.setNumPendingBipRequests(0);
            } else {
                //  boolean cScws = sim.getProfile().getCardType().getScws_support();
                if (numOpenRequests >= ServerSettings.getScWsNumberOfRetries())
                    sim.setNumPendingRAMRequests(0); // Reset it.
            }
            sim.setLastDataPlanFetch(Calendar.getInstance().getTime());

            // em.persist(sim); // Update it to the DB
        }
        return hasDataPlan;
    }
    /**
     * @brief Transport message status after sending.
     */
    public enum MessageStatus {
        NA, NotSent, SendFailed, SendFailedFatal, BipWait, BipPushSent, Sent, BipPushConfirmed, Wait, HttpWait,
        HttpPushSent, HttpPushConfirmed;

        public static final Map<MessageStatus,Transport> statusMap = new ConcurrentHashMap<>();
        public Transport toTransport() {
            // Returns a transport object that can process this thingie...
            return statusMap.get(this);
        }
    }

    public enum  TransportType {
        NA, WS, BIP, RAMHTTP, SMS;

        public static final Map<TransportType,Transport> transportMap = new ConcurrentHashMap<>();
        public Transport toTransport() {
            return transportMap.get(this);
        }
    }


    /**
     * @brief handle a received DLR
     * @param po
     * @param em
     * @param msisdn - the msisdn
     * @param id - the transaction log ID
     * @param dlrCode - The Dlr code
     * @param allDelivered - whether all messages delivered
     */
    private static void processDlr(PersistenceUtility po, EntityManager em, String msisdn, long id, int dlrCode, boolean
            allDelivered) {}


    /**
     * @brief the transport context. This object holds key information used by the transport layer (e.g. for BIP
     * the connection object, or the push message)
     */
    public class Context {
        // The context

        public long maxMessageSize = 0;
        public boolean allowChaining = false; // By default, no chaining.
        public Eis sim = null;
        public String tag = null;
        public long tagId = -1; // Used for DLR tracking.
        public String requestID = null;

        public boolean ucs2Sms = false;
        public boolean no0348coding = false;

        public Context(Eis sim, int maxMessageSize,
                       boolean allowChaining,
                       boolean ucs2Sms, boolean no0348coding) {
            this.sim = sim;
            this.maxMessageSize = maxMessageSize;
            this.allowChaining = allowChaining;

            this.ucs2Sms = ucs2Sms;
            this.no0348coding = no0348coding;
        }

        public void destroy() {
            // Cleanup
        }
    }
}
