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
import io.njiwa.common.StatsCollector;
import io.njiwa.common.Utils;
import io.njiwa.common.model.KeyComponent;
import io.njiwa.common.model.KeySet;
import io.njiwa.common.model.TransactionType;
import io.njiwa.sr.Session;
import io.njiwa.sr.model.Eis;
import io.njiwa.sr.model.SecurityDomain;
import io.njiwa.sr.model.SmSrTransaction;
import io.njiwa.sr.ota.Ota;
import io.njiwa.sr.transactions.SmSrBaseTransaction;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.util.Strings;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.annotation.Resource;
import javax.ejb.ConcurrencyManagement;
import javax.ejb.ConcurrencyManagementType;
import javax.ejb.Singleton;
import javax.ejb.Startup;
import javax.enterprise.concurrent.ManagedExecutorService;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.persistence.EntityManager;
import javax.persistence.LockModeType;
import javax.ws.rs.core.Response;
import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;


/**
 * @brief HTTP transport mechanism
 * @details This module implements the HTTP Transport mechanism according to GPC Ammendment B. It consists
 * of the following sub-components:
 * - A TLS server module: This listens on a dedicated port for TCP/IP connections. It then performs a PSK-TLS handshake
 * and records the ID of the SIM card that has connected (assuming TLS handshake completes correctly)
 * - An HTTP server that runs on top of the TLS connection: This parses and composes HTTP messages. Each HTTP request is
 * routed to the relevant SCWS or RAM module, which then sends out the command packet. The HTTP response is then sent
 * to the
 * card. Likewise any response from the card is passed to the relevant module for processing
 * - A RAM module to compose RAM commands for sending via HTTP
 */
@Singleton(name = "RamHTTP")
@Startup
@ConcurrencyManagement(ConcurrencyManagementType.BEAN)
public class RamHttp extends Transport {
    public static final String PROP_APDU_FORMAT_PARAM = "ram-http-proprietary-apdu-format";
    public static final String RAM_HTTP_ADMIN_AGENT_TAR = "B20100"; //!< RAM Admin Agent TAR value
    public static final String DISPATCHER_URI = ServerSettings.getRamPollingUri(); //!< The Dispatcher URL for HTTP
    // over TLS
    public static final String DISPATCHER_RESULT_URI = "ramNext";

    public static final byte[] RAM_HTTP_ADMIN_AGENT_TAR_B;
    public static final short ADMIN_SESSION_TRIGGER_PARAMS_TAG = 0x81; //!< The top-level PUSH SMS TAG
    public static final short CONFIGURATION_RESOURCE_URL_TAG = 0x82; //!<  SCWS config resource PUSH SMS TAG
    public static final short SECURITY_DOMAIN_PARAMS_TAG = 0x83; //!< Agent config resource PUSH SMS TAG
    public static final short CONNECTION_PARAMS_TAG = 0x84; //!<  Connection params in PUSH SMS TAG
    public static final short SECURITY_DOMAIN_ADMIN_SESSION_PARAMS_TAG = 0x85; //!<  Security params in PUSH SMS TAG
    public static final short RETRY_POLICY_PARAMS_TAG = 0x86; //!< Retry policy in PUSH SMS TAG
    public static final byte RETRY_FAILURE_REPORT_TAG = (byte) 0x87; //!< Retry failure report in PUSH SMS TAG
    public static final String APPLICATION_VND_GPC = "application/vnd.globalplatform.card-content-mgt;version=1.0";
    //!< RAM over HTTP content type
    public static final String APPLICATION_VND_ETSI_SCP_COMMAND =
            "application/vnd.etsi.scp.command-data;version=1.0"; //!< ETSI TS TS 102 225 content type for APDU dispatch
    public static final short ADMIN_HTTP_POST_PARAMS_TAG = 0x89; //!< Post params in PUSH SMS TAG
    public static final short ADMIN_HOST_PARAM_TAG = 0x8A;
    public static final short AGENT_ID_PARAM_TAG = 0X8B; //!< Agent-ID in PUSH SMS TAG
    public static final short ADMIN_URI_PARAM_TAG = 0X8C; //!< Admin URI in PUSH SMS TAG
    public static final byte TIMER_VALUE_BER_TAG = (byte) 0xA5; //!< Timer value tag, from ETSI TS 101 220 Sec 7.2
    public static final int HTTP_HEADER_LEN = 286 + 10; //!< The approximate length of our HTTP message header
    public static final int POR_FLAG = 0x00; //!< Whether to request Proof-of-receipt for Push messages. Set to 0x1
    // to get PoR
    private static final int DEFAULT_HTTP_BUFFER_LEN = 1024; //!< The default HTTP buffer length, less headers.
    private static final short ADMIN_AGENT_FAILURE_REPORT_TAG = 0x88;
    private static final boolean ALLOW_RAM_COMMAND_CHAINING = false; //!< Whether to allow command chaining for RAM
    private static final short PSK_ID_SGP_FORMAT = 0x80;
    private static final short PSKID_EID_TAG = 0x81;
    private static final short PSKID_AID_TAG = 0x4F;
    private static final short PSK_KEY_ID_TAG = 0x82;
    private static final short PSK_KEY_VERSION_TAG = 0x83;
    public static final int[] SUPPORTED_CIPHERS = {CipherSuite.TLS_PSK_WITH_3DES_EDE_CBC_SHA, CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256,
            // CipherSuite.TLS_PSK_WITH_NULL_SHA,
            CipherSuite.TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA, CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA};
    private static boolean ramHttpStarted = false;

    static {
        RAM_HTTP_ADMIN_AGENT_TAR_B = Utils.HEX.h2b(RAM_HTTP_ADMIN_AGENT_TAR);
        RamHttp r = new RamHttp();
        MessageStatus.statusMap.put(MessageStatus.HttpPushConfirmed, r);
        MessageStatus.statusMap.put(MessageStatus.HttpWait, r);
        MessageStatus.statusMap.put(MessageStatus.HttpPushSent, r);

        TransportType.transportMap.put(TransportType.RAMHTTP, r);
    }

    @Inject
    Sms smsTransport; //!< SMS transport link: We need this to send admin commands using the simplified protocol.
    @Inject
    Instance<PersistenceUtility> poTasks; //!< Persistence util pool for database transactions

    @Resource
    private ManagedExecutorService runner; //!< This is the thread pool for running the TLS client connections

    private PskTlsAdminServer tlsAdminServer = new PskTlsAdminServer(); //!< This is the PSK TLS server

    public RamHttp() {
        unit = "byte(s)";

    }

    private static String formatRamHTTPXAdminFrom(Eis sim)  {
        String eid = sim.getEid();
        SecurityDomain sd = sim.findISDR();

        String isdr_aid = sd.getAid();
        return String.format("//se-id/eid/%s;//aa-id/aid/%s", eid, Utils.ramHTTPPartIDfromAID(isdr_aid));
    }

    /**
     * @brief On startup, start the TLS server.
     */
    @PostConstruct
    @Override
    public synchronized void start() {
        try {
            tlsAdminServer.startUp(); // Try to start it.
            started = ramHttpStarted = true;
            String ipAddr;
            try {
                ipAddr = InetAddress.getByAddress(ServerSettings.getBip_network_interface()).toString();
            } catch (Exception ex) {
                ipAddr = "127.0.0.1";
            }
            int port = ServerSettings.getRamhttpAdminPort();
            Utils.lg.info(String.format("SCWS Admin startup complete: IP [%s], port = %s", ipAddr, port));
        } catch (Exception ex) {
            Utils.lg.severe(String.format("RAM HTTP Admin startup failed: %s", ex));
        }
    }

    @PreDestroy
    @Override
    public synchronized void stop() {
        try {
            tlsAdminServer.stop();
            ramHttpStarted = started = false;
        } catch (Exception ex) {

        }
    }

    @Override
    public boolean processTransMessageStatus(EntityManager em, SmSrTransaction bt, boolean success, boolean retry,
                                             byte[] data) {
        MessageStatus status = bt.getTransportMessageStatus();
        boolean psent = status == MessageStatus.HttpPushSent;
        if (psent) {
            // Update status
            bt.setStatus(success ? SmSrTransaction.Status.HttpWait : SmSrTransaction.Status.Ready);
            bt.setSimStatusCode(Utils.HEX.b2H(data));

            bt.setLastupdate(Calendar.getInstance().getTime());

            bt.setSimStatusCode(success ? "" : "RAM HTTP PUSH Failed");


        }
        return !psent; // Continue processing if this was not a push confirmation.
    }

    @Override
    public String getName() {
        return "RAMHTTP";
    }

    @Override
    public TransportType sendMethod() {
        return TransportType.RAMHTTP;
    }

    /**
     *
     * @param bt
     * @param otaParams
     * @return
     * @throws Exception
     * @brief Make a request HTTP message structure out of the batch transaction parameters
     */
    private Utils.Triple<byte[], Map<String, String>, String> makePkg(final SmSrTransaction bt, Ota.Params otaParams) throws Exception {

        SmSrBaseTransaction ttype = bt.getTransObject();
        if (!ttype.hasMore()) return null;
        Ota.ScriptChaining chaining = ttype.commandChainingType(otaParams, bt.getMoreToFollow());
        Utils.Pair<byte[], Integer> xres = Ota.mkOTAPkg(otaParams, ttype.cAPDUs, ttype.index,
                (l) -> l < DEFAULT_HTTP_BUFFER_LEN,chaining);
        ttype.lastIndex = xres.l;
        byte[] body = xres.k;
        if (body == null) return null;
        final String targetApp = otaParams.getHTTPargetApplication();
        Map<String, String> hdrs = new HashMap<String, String>() {
            {
                put("X-Admin-Next-URI", String.format("/%s/%s", RamHttp.DISPATCHER_RESULT_URI, bt.getId())); // Put
                // in response URI
                // put("X-Admin-From", formatRamHTTPXAdminFrom(sim));
                if (targetApp != null) put("X-Admin-Targeted-Application", String.format("//aid/%s", targetApp));
                put("X-Admin-Protocol", "globalplatform-remote-admin/1.0");
            }
        };

        return new Utils.Triple<>(body, hdrs, APPLICATION_VND_GPC);
    }

    /**
     * @param em
     * @param bt
     * @param closeConn
     * @return
     * @brief Convert a batch transaction into a HTTP transaction to be sent to the card
     */
    private Utils.Http.Response transactionToRequest(EntityManager em, final SmSrTransaction bt, boolean closeConn) {
        Utils.Http.Response resp;
        // Get the batch first of all:
        try {
            // Check if it is not already sent.
            SmSrTransaction.Status status = bt.getStatus();
            if (status != SmSrTransaction.Status.HttpWait && status != SmSrTransaction.Status.Ready && status != SmSrTransaction.Status.InProgress && status != SmSrTransaction.Status.Sent)
                throw new Exception("This transaction has already completed. Will not re-send it");
            Eis euicc = em.find(Eis.class, bt.getEis_id(), LockModeType.PESSIMISTIC_WRITE);
            euicc.setLastRAMHttpRequest(Calendar.getInstance().getTime()); // Update date of last HTTP

            // int tkCount = tparams.size();

            String targetAID = bt.getTargetAID(); // Get the target AID

            Ota.Params otaParams = new Ota.Params(euicc, targetAID, null);
            // Make a HTTP response object, containing the commands to be sent:
            Utils.Triple<byte[], Map<String, String>, String> xres = makePkg(bt, otaParams);

            byte[] body = xres.k;

            Map<String, String> hdrs = xres.l;
            String ctype = xres.m;

            int retryInterval = ServerSettings.getRetryInterval();
            int retries = bt.getRetries();
            int xretries = retries + 1;
            Date now = Calendar.getInstance().getTime();
            long tnow = now.getTime();
            long secs = ServerSettings.isGeometricBackOff() ? (retryInterval * xretries) : retryInterval;
            Date afterT = new Date(tnow + secs * 1000);

            // Update it as well
            bt.setNextSend(afterT);
            bt.setStatus(SmSrTransaction.Status.InProgress); // Mark it as sent. Right?
            bt.setLastTransportUsed(TransportType.RAMHTTP);
            bt.setRetries(retries + 1);


            resp = new Utils.Http.Response(Response.Status.OK, hdrs, ctype, body, closeConn);

            otaParams.postProcessChainingInfo(); // Handle chaining stuff...
            //   em.flush(); // Force the changes out. Right?
        } catch (Exception ex) {
            resp = new Utils.Http.Response(Response.Status.NO_CONTENT, null, null, null, closeConn);
            Utils.lg.severe(String.format("RAMHTTP.admin.endpoint: Received request to fetch transaction [%s] but " + "failed to find it: %s", bt == null ? -1L : bt.getId(), ex));
        }
        return resp;
    }

    private Utils.Http.Response transactionToRequest(EntityManager em, final long tid, boolean closeConn) {
        return transactionToRequest(em, em.find(SmSrTransaction.class, tid, LockModeType.PESSIMISTIC_WRITE), closeConn);
    }

    /**
     * @param em
     * @param bt
     * @param input
     * @param r
     * @param success
     * @param xstatus
     * @brief Given a single HTTP response, process it, record the result against the transaction
     */
    private void processSingleResponse(EntityManager em, SmSrTransaction bt, byte[] input,
                                       boolean success, String xstatus) throws Exception {
        // XXX This bit is copied largely from Ota.processMO(). Perhaps we should refactor?


        try {
            long t = Calendar.getInstance().getTimeInMillis();
            String reqid = String.format("%d", t); // Make fake ReqID
           TransactionType trobj =  bt.getTransObject();
            trobj.handleResponse(em, bt.getId(), success ? TransactionType.ResponseType.SUCCESS :
                    TransactionType.ResponseType.ERROR, reqid, input); // Do success
        } catch (Exception ex) {

        }

        SmSrTransaction.Status newStatus = bt.statusFromResponse(success, false);

        bt.updateStatus(em, newStatus);

        Date dt = newStatus != SmSrTransaction.Status.Ready ? Utils.infiniteDate : Calendar.getInstance().getTime();
        bt.setNextSend(dt); // Set next date
        bt.setLastupdate(Calendar.getInstance().getTime());
        if (success) bt.setLastrequestID(null); // Clear request ID.
        bt.setSimStatusCode(xstatus);
        bt.setSimResponse(xstatus);

        bt.deleteTransactionRequestIds();
        // SmSrTransactionRequestId.deleteTransactionRequestIds(em, bt.getId());
    }

    /**
     * @param em
     * @param sim
     * @param tid
     * @param scriptStatus
     * @param input
     * @param closeConn @return
     * @brief When a HTTP response is received as a response to an APDU sequence sent, process it.
     */
    private Utils.Http.Response processResponse(EntityManager em, Eis sim, final long tid, String scriptStatus, byte[] input, boolean closeConn) {
        Utils.Http.Response resp;
        // Find the transaction and process the response.
        try {
            boolean executeOK = scriptStatus == null || scriptStatus.equalsIgnoreCase("ok");

            // Parse the response first, but only if we had success...
            Ota.ResponseHandler.RemoteAPDUStructure rp = executeOK ? Ota.ResponseHandler.RemoteAPDUStructure.parse(input) :
                    Ota.ResponseHandler.ETSI102226APDUResponses.createGenericErrorResponse(scriptStatus);
            SmSrTransaction nextBt;


            if (rp instanceof Ota.ResponseHandler.ETSI102226APDUResponses) {
                SmSrTransaction bt = em.find(SmSrTransaction.class, tid, LockModeType.PESSIMISTIC_WRITE);
                SmSrBaseTransaction tobj = bt.getTransObject();
                byte[] output = rp.getData();
                Ota.ResponseHandler.ETSI102226APDUResponses r = (Ota.ResponseHandler.ETSI102226APDUResponses) rp;

                boolean success = r.isSuccess; // Whether success
                String xstatus = r.formattedResponse;

                tobj.setResponses(r);
                processSingleResponse(em, bt, output,   success, xstatus);
                nextBt = success ? bt.findNextAvailableTransaction(em) : null;
                //  em.flush(); // Right?
            } else {
                // Just a notification: handle it
                Session session = new Session(em, sim);
                nextBt = Ota.processNotification(rp.getData(), TransportType.RAMHTTP, session); // Get the one to
                // send next.
            }
            // Now get the next one in sequence, if any
            if (nextBt != null) {
                nextBt.setNextSend(Calendar.getInstance().getTime()); // Set to go out
                resp = transactionToRequest(em, nextBt, closeConn);
            } else resp = new Utils.Http.Response(Response.Status.NO_CONTENT, null, null, null, closeConn);
        } catch (Exception ex) {
            resp = new Utils.Http.Response(Response.Status.NO_CONTENT, null, null, null, closeConn);
            Utils.lg.severe(String.format("RamHTTP.admin.endpoint: Received response to a transaction [%s] but had " + "problems processing it: %s", tid, ex));
        }
        return resp;
    }

    /**
     * @param sim       The Sim card
     * @param otaParams The OTA parameters
     * @param transID   The transaction ID
     * @param pktSize   The packet size
     * @return
     * @brief Get a context object. Our context are special here:
     * - They keep track of whether we have an actual connection or not
     * - They keep provide the push message if needed
     * - They modify the OTA parameters (specifically SPI) to ensure PUSH doesn't fail
     */
    @Override
    public Context getContext(Eis sim, Ota.Params otaParams, long transID, int pktSize) {

        try {

            // boolean useRamHttp = getHttpInfo(em, sim);
            int numOpens = sim.getNumPendingRAMRequests();

            Context ctx = new Context(sim, transID, pktSize);
            // Check whether to force a push command
            Date lastHttpCommand = sim.getLastRAMHttpRequest();
            Date lastpushRequest = sim.getLastRAMPushRequest();

            long tnow = System.currentTimeMillis();

            // Have we seen a HTTP command recently and are being asked to use HTTP? If so, do not force push
            if (!ctx.useSms && !otaParams.forcePush && lastHttpCommand != null && tnow - lastHttpCommand.getTime() < ServerSettings.getRAMAdminHttpKeepAliveTimeOut())
                ctx.forcePush = false;
            else // We have no recent http fetchAFew and we need to push? Then do so.
                ctx.forcePush = otaParams.forcePush = !ctx.useSms && // Only if not using SMS
                        (otaParams.forcePush || (lastpushRequest == null || tnow - lastpushRequest.getTime() > numOpens * ServerSettings.getRamPushRetryTimeOut() * 1000));
            if (ctx.forcePush) {
                // Set the TAR value
                SecurityDomain sd = sim.findISDR();

                otaParams.sd = sd; // For push purposes
                if ((otaParams.spi2 & 0x01) != 0)
                    otaParams.spi2 = ((otaParams.spi2 & ~3)) & 0xFF | POR_FLAG; // PoR on error only.
            } // Keep whatever was set

            return ctx;
        } catch (Exception ex) {
            return null;
        }
    }

    /**
     * @param context
     * @param dlen
     * @return
     * @brief Check if we have enough on-SIM buffer for a message of this size.
     * If using SMS, simply check the CSMS buffer size. If not, check SIM HTTP buffer size.
     */
    @Override
    public boolean hasEnoughBuffer(Transport.Context context, int dlen) {
        Context ctx = (Context) context;

        if (ctx.useSms) return smsTransport.hasEnoughBuffer(context, Ota.smsCount(dlen));
        else return super.hasEnoughBuffer(context, dlen);
    }

    /**
     * @param em
     * @param context
     * @param text
     * @return
     * @brief Compute the message to send: Either a PUSH or the raw message.
     */
    @Override
    public byte[] messageToSend(EntityManager em, Transport.Context context, Ota.Params params, byte[] text) {
        Context ctx = (Context) context;
        // If we are using push, return the push command
        if (ctx.forcePush) {
            params.porOnError = true;
            return ctx.pushCmd;
        }
        return text; // Otherwise return the bare message, and let the send function deal with issues...
    }

    @Override
    public String getUnit(Transport.Context context) {
        Context ctx = (Context) context;
        if (ctx.forcePush || ctx.useSms) return smsTransport.getUnit(context);
        return unit;
    }

    @Override
    public Utils.Triple<Integer, MessageStatus, Long> sendMsg(EntityManager em, Transport.Context context, byte[] msg
            , int dlr_flags) throws Exception {
        Context ctx = (Context) context;

        boolean useSms = ctx.forcePush || ctx.useSms;
        Eis sim = ctx.sim;
        if (useSms) {
            Date tnow = Calendar.getInstance().getTime();
            if (ctx.forcePush) {
                Utils.lg.info(String.format("RAMHTTP: Preparing to send PUSH to [%s] for trans [#%s]",
                        ctx.sim.activeMISDN(), ctx.tid));
                sim.setLastRAMPushRequest(tnow);
                sim.setNumPendingRAMRequests(sim.getNumPendingRAMRequests() + 1);
            }
            Utils.Triple<Integer, MessageStatus, Long> xres = smsTransport.sendMsg(em, context, msg, ctx.forcePush ?
                    DLR_DELIVERED_TO_PHONE : dlr_flags); // When using the simple protocol, track as usual
            MessageStatus status;
            long nextt;

            if (ctx.forcePush) {
                status = xres.l == MessageStatus.Sent ? MessageStatus.HttpPushSent : MessageStatus.HttpWait;
                nextt = (1 + sim.getNumPendingRAMRequests()) * ServerSettings.getRamPushRetryTimeOut();
            } else {
                status = xres.l; // Transmit as received.
                nextt = xres.m;
            }
            return new Utils.Triple<>(xres.k, status, nextt);
        } else
            // Must wait a little for the HTTP Agent on the card to actively fetchAFewPending the message.
            return new Utils.Triple<>(0, MessageStatus.HttpWait, ServerSettings.getRamPushRetryTimeOut() * 1000L);
    }

    /**
     * @param sim
     * @return
     * @brief Make a PSK ID for a SIM card
     * @details Given a SIM, get its ICCID and also get the master key label from the SIM profile.
     * Construct the PSK ID according to our internal rules.
     */
    private Utils.Pair<byte[], byte[]> makePskId(Eis sim) {

        // Make the PskId from the ICCID, master key label as per GT spec
        try {
            final SecurityDomain sd = sim.findISDR();
            final String eid = sim.getEid();
            // Find first usable key:
            // 1. Find SCP81 keyset

            KeyComponent pskKeyComponent = sd.findFirstSCP81Key();
            int keyIdx = pskKeyComponent.getKey().getIndex();
            int keyVer = pskKeyComponent.getKey().getKeyset().getVersion();

            // See Table 4 of SGP02 v4.1
            byte[] rawPsk = new ByteArrayOutputStream() {
                {
                    Utils.BER.appendTLV(this, PSK_ID_SGP_FORMAT, new byte[]{0x02});
                    byte[] xeid = Utils.HEX.h2b(eid);
                    Utils.BER.appendTLV(this, PSKID_EID_TAG, xeid);
                    byte[] xaid = Utils.HEX.h2b(sd.getAid());
                    Utils.BER.appendTLV(this, PSKID_AID_TAG, xaid);

                    Utils.BER.appendTLV(this, PSK_KEY_ID_TAG, new byte[]{(byte) keyIdx});
                    Utils.BER.appendTLV(this, PSK_KEY_VERSION_TAG, new byte[]{(byte) keyVer});
                }
            }.toByteArray();

            // This is as per Sec 3.7.3 of the GP RAM HTTP doc
            byte[] version = new byte[]{(byte) keyVer, (byte) keyIdx};
            // SGP.02 says the Psk ID must be UTF-8 encoded hex. so...
            return new Utils.Pair<>(Utils.HEX.b2H(rawPsk).getBytes(StandardCharsets.UTF_8), version);

        } catch (Exception ex) {
            String xs = ex.getMessage();
        }
        return new Utils.Pair<>(new byte[0], new byte[0]);
    }

    /**
     * @param em    Entity Manager
     * @param pskID PSK ID
     * @return
     * @throws Exception
     * @brief Given a PSK ID, return the PSK
     * @details From the PSK ID we extract the ICCID (and from that find the SIM),
     * and the master key hash. We lookup the master key from the
     * SIM profile. The PSK is then derived based on these two
     */
    private Utils.Pair<byte[], Long> makeTlsPskFromPskId(EntityManager em, byte[] pskID) throws Exception {
        byte[] input = Utils.HEX.h2b(pskID);
        ByteArrayInputStream in = new ByteArrayInputStream(input);
        Utils.Pair<InputStream, Integer> res = Utils.BER.decodeTLV(in);
        int tag = res.l;

        if (tag == PSK_ID_SGP_FORMAT) {
            byte[] eid = null;
            byte[] aid = null;
            int keyversion = -1, keyindex = -1;
            while (in.available() > 0 && (res = Utils.BER.decodeTLV(in)) != null) {
                byte[] data = Utils.getBytes(res.k);

                if (res.l == PSKID_EID_TAG) eid = data;
                else if (res.l == PSKID_AID_TAG) aid = data;
                else if (res.l == PSK_KEY_ID_TAG) keyindex = data[0];
                else if (res.l == PSK_KEY_VERSION_TAG) keyversion = data[0];
            }

            // Get the SIM
            String xeis = Utils.HEX.b2H(eid);
            Eis sim = Eis.findByEid(em, xeis);
            if (sim == null)
                throw new Exception(String.format("No such euicc [%s] in received PSK ID [%s]", xeis,
                        Utils.HEX.b2H(pskID)));
            SecurityDomain isdr = sim.findISDR(); // Ignore the AID, right?

           // Find key component
            KeyComponent kc = isdr.findKeyComponent(KeySet.Type.SCP81,keyversion,keyindex, KeyComponent.Type.PSK_TLS);
            if (kc == null)
                throw new Exception(String.format("No such key with version=%02x, index = %02x received in TLS " +
                        "handshake with euicc [%s]", keyversion, keyindex, xeis));
            // We should have a key now..
            return new Utils.Pair<>(kc.byteValue(), sim.getId());
        }

        return null;
    }

    /**
     * @brief This is the PSK-TLS server
     * @detail This class implements the PSK-TLS server proper. It starts a single thread listening on the
     * TLS port for incoming connections. When a connection is received, a new processing task is
     * created for it (using the HttpTlServer class) and submitted to the thread pool for execution.
     */
    private class PskTlsAdminServer {
        Thread th = null; //!< The server execution thread
        private int port = ServerSettings.getRamhttpAdminPort(); //!< The server port from the configuration
        private int backlog = ServerSettings.getRamAdminBackLog(); //!< The server port back log
        private ServerSocket socket = null; //!< The server socket

        public void startUp() throws Exception {

            socket = new ServerSocket(port, backlog);

            // Start the server thread
            th = new Thread(() -> {
                Utils.lg.info(String.format("Starting Ram HTTP admin agent port handler on [%s]...", port));
                while (true) try {
                    Socket client = socket.accept();
                    HttpTlsServer server = new HttpTlsServer(client);
                    runner.submit(server); // Put it on queue and go away...
                } catch (Exception ex) {
                    // All others close it.
                    break;
                }
                Utils.lg.info(String.format("Stopping Ram HTTP admin agent port handler on [%s]", port));

            });
            th.start();
        }

        public void stop() throws Exception {
            socket.close(); // Close the socket
            socket = null;
            th.interrupt(); // Interrupt and close thread
            th.join(1000); // Wait for it

        }

        /**
         * @brief This is our Identity Manager for PSK-TLS. It's main function is to handle/process
         * PSK Ids. So when a TLS client requests our PSK, this class generates one from the
         * identity according to our internal rules.
         */
        private class IdentityManager implements TlsPSKIdentityManager {
            private Long simId;

            @Override
            public byte[] getHint() {
                return null; // No hint is given to clients. Right?
            }

            @Override
            public byte[] getPSK(final byte[] identity) {
                if (identity != null) {
                    PersistenceUtility po = poTasks.get();
                    // Get the Key from the bytes
                    return po.doTransaction((PersistenceUtility unused, EntityManager em) -> {
                        Utils.Pair<byte[], Long> res = makeTlsPskFromPskId(em, identity);
                        simId = res.l;

                        return res.k;
                    });
                } else return null;
            }

            public Long getSimId() {
                return simId;
            }

        }

        /**
         * @brief This is the TLS HTTP server proper
         * @details This class implements the TLS HTTP server. It performs the TLS handshake, reads
         * HTTP requests, passes the requests to the upper layer (RAM HTTP or Scws),
         * gets the HTTP response and sends it to the client (SIM) via TLS.
         */
        private class HttpTlsServer implements Runnable {

            private static final int HTTP_SOCKET_WAIT_FACTOR = 10;
            private Socket socket;

            public HttpTlsServer(Socket socket) {
                this.socket = socket;
            }

            /**
             * @brief Perform the client handshake, then process HTTP transactions as received
             */
            @Override
            public void run() {
                try {
                    // SecureRandom srand = new SecureRandom();

                    TlsServerProtocol s = new TlsServerProtocol(socket.getInputStream(), socket.getOutputStream());
                    final PskTlsServ tlsServer = new PskTlsServ();
                    s.accept(tlsServer);
                    final InputStream in = s.getInputStream();
                    final OutputStream out = s.getOutputStream();

                    socket.setSoTimeout(HTTP_SOCKET_WAIT_FACTOR * ServerSettings.getRAMAdminHttpKeepAliveTimeOut() * 1000);
                    PersistenceUtility po = poTasks.get();
                    po.doTransaction((po1, em) -> {
                        runHttpSession(em, in, out, tlsServer.getSimId());
                        return null;
                    });

                    socket.close(); // Close it
                    // s.close(); // Do we need this?
                } catch (Exception ex) {
                    Utils.lg.severe(String.format("Failed to run PSK-TLS http session: %s", ex));
                }
            }

            /**
             * Process an HTTP session from the card: Parse http packet, call the relevant function internally to
             * process the data received
             *
             * @param em
             * @param in
             * @param out
             * @param simId
             */
            private void runHttpSession(EntityManager em, InputStream in, OutputStream out, Long simId) {
                // Do the actual HTTP transactions
                int maxReqs = ServerSettings.getRAMAdminHttpMaxRequests();
                int reqs = 0;

                while (reqs < maxReqs) try {

                    Utils.Http.Request req = new Utils.Http.Request(in);

                    long tid;

                    reqs++;
                    // Try to get the IDs from the args array
                    try {
                        tid = Long.parseLong(req.args[req.args.length - 1]);
                    } catch (Exception ex) {
                        tid = -1;
                    }
                    Eis euicc = em.find(Eis.class, simId, LockModeType.PESSIMISTIC_WRITE); // Get the SIM card,
                    // right??
                    euicc.setNumPendingRAMRequests(0); // Clear the number of pending requests. We got a connection.

                    // em.flush(); // Force changes out. Right?
                    Utils.Http.Response response;
                    boolean closeConn = (reqs == maxReqs);
                    String xAdminFrom = req.headers.get("X-Admin-From");
                    String xResponseStatus = req.headers.get("X-Admin-Script-Status");
                    Object msgData = req.cgiParams.get("msg");
                    boolean hasMsgData = (msgData != null) && (msgData instanceof String); // Sec 3.15.2
                    // notification via HTTPS: It is hex-coded as per spec
                    byte[] inputData = hasMsgData ? Utils.HEX.h2b((String) msgData) : req.body;

                    if (hasMsgData || req.uriVerb.equalsIgnoreCase(RamHttp.DISPATCHER_RESULT_URI) || xResponseStatus != null) {
                        Utils.lg.info(String.format("Incoming HTTP request, x-script-status: %s, xfrom: %s, body: %s",
                                xResponseStatus != null ? xResponseStatus : "",
                                xAdminFrom != null ? xAdminFrom : "",
                                msgData));
                        StatsCollector.recordTransportEvent(TransportType.RAMHTTP, PacketType.MO); // Record
                        // incoming stat
                        response = processResponse(em, euicc, tid, xResponseStatus, inputData, closeConn);
                    } else /* if (req.uriVerb.equalsIgnoreCase(DISPATCHER_URI)) */ {
                        if (tid < 0) try {
                            SmSrTransaction bt = SmSrTransaction.findfirstTransaction(em, euicc.getId(),
                                    SmSrTransaction.Status.HttpWait);
                            tid = bt.getId();
                        } catch (Exception ex) {
                        }
                        response = transactionToRequest(em, tid, closeConn);
                    }
                        /*
                        else
                            response = new Utils.Http.Response(Response.Status.FORBIDDEN, null, null, null, closeConn);
                            */
                    response.version = req.version; // Copy version over.
                    response.outputMessage(out);

                    if (response.status == Response.Status.OK)
                        StatsCollector.recordTransportEvent(TransportType.RAMHTTP, PacketType.MT);
                } catch (Exception ex) {
                    break; // We are done
                }

            }
        }

        /**
         * @brief The TLS server, sub-classing the BouncyCastle class.
         * @details We need this class so that we can customise the list of supported TLS ciphers and also
         * customise the PSK identity manager so that we can generate our own PSK from the identity.
         */
        private class PskTlsServ extends PSKTlsServer {
            private IdentityManager identityManager;

            public PskTlsServ() {
                super(new BcTlsCrypto(new SecureRandom()), new IdentityManager());
                identityManager = (IdentityManager) this.pskIdentityManager;
            }

            @Override
            public void notifyClientVersion(ProtocolVersion version) throws IOException {
                Utils.lg.info(String.format("Received TLS client v%s", version));
            }

            @Override
            public void notifyOfferedCipherSuites(int[] offered) throws IOException {
                super.notifyOfferedCipherSuites(offered);

            }
            // Cipher suites
            @Override
            protected int[] getSupportedCipherSuites() {
                return SUPPORTED_CIPHERS;
            }

            @Override
            public int[] getCipherSuites() {
                return SUPPORTED_CIPHERS;
            }

            public Long getSimId() {
                return identityManager.getSimId();
            }

            @Override
            public void notifySecureRenegotiation(boolean secureRenegotiation) throws IOException
            {
                // Do nothing.....
                Utils.lg.info("TLS-PSK server re-negotiated set to " + secureRenegotiation);
            }

            @Override
            public ProtocolVersion getMaximumVersion() {
                return ProtocolVersion.TLSv12;
            }


            protected ProtocolVersion[] getSupportedVersions() {
                return ProtocolVersion.TLSv12.only();
            }

            @Override
            public boolean shouldUseGMTUnixTime()
            {
                return true;
            }

            @Override
            public ProtocolVersion getServerVersion() throws IOException {
                ProtocolVersion serverVersion = super.getServerVersion();

                Utils.lg.info("TLS-PSK server negotiated " + serverVersion);

                return serverVersion;
            }

            @Override
            public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause) {
                String msg =
                        "TLS-PSK server raised alert: " + AlertLevel.getText(alertLevel) + ", " + AlertDescription.getText(alertDescription);
                if (message != null) {
                    msg += "> " + message;
                }

                if (cause != null) msg += ": " + cause.toString();
                if (alertLevel == AlertLevel.fatal) Utils.lg.severe(msg);
                else Utils.lg.info(msg);
            }

            @Override
            public void notifyAlertReceived(short alertLevel, short alertDescription) {
                String msg =
                        "TLS-PSK server received alert: " + AlertLevel.getText(alertLevel) + ", " + AlertDescription.getText(alertDescription);
                if (alertLevel == AlertLevel.fatal) Utils.lg.severe(msg);
                else Utils.lg.info(msg);
            }

            @Override
            public void notifyHandshakeComplete() throws IOException {
                super.notifyHandshakeComplete();

                byte[] pskIdentity = context.getSecurityParameters().getPSKIdentity();
                if (pskIdentity != null) {
                    String name = Strings.fromUTF8ByteArray(pskIdentity);
                    System.out.println("TLS-PSK server completed handshake for PSK identity: " + name);
                }
            }

            // XX Do we need getRSAEncryptionCredentials()??
        }



    }

    /**
     * @brief This is our Context class, sub-classing the one in Transports.
     */
    private class Context extends Transport.Context {
        public long tid; //!< The transaction that caused the PUSH
        public boolean forcePush = false; //!< Whether to force  a PUSH message
        public byte[] pushCmd = null; //!< The push command, if we need to do a push
        public boolean useSms;
        public boolean useRamHttp; //!< Whether to use GP RAM over HTTP.

        public Context(Eis sim, long tid, int pktSize) {
            super(sim, DEFAULT_HTTP_BUFFER_LEN, false, false, false);
            this.tid = tid;

            // Always honour the RamHTTP flag. Right?
            if (pktSize > Sms.MAX_CSMS) {
                useSms = false;
                useRamHttp = true;
                try {
                    pushCmd = makeRAMHttpPushCommand(sim);
                } catch (Exception ex) {
                    Utils.lg.severe(String.format("RAM.getContext(%s, tid=%s): Failed to make Push command: %s", sim,
                            tid, ex));
                }
            } else useSms = true;
        }

        /**
         * @param sim
         * @return
         * @throws Exception
         * @brief Make the Push command
         * @details Make the GPC Ammend B PUSH Command for a given eUICC
         * See Sec 3.7.1 of GPC Ammendment B v1.1.2
         */
        private byte[] makeRAMHttpPushCommand(final Eis sim) throws Exception {

            if (ServerSettings.getRamUseDefaultConfig())
                return new byte[]{(byte) 0x81, 0x00}; // XX really?

            // Now build the agent conf params according to Sec 13.3.2.9.2 of the SCWS or Sec 3.7 of GP 2.2 Adendum B
            byte[] secDomainAdminSessionParams = new ByteArrayOutputStream() {
                {
                    // Make the connection params: Use the BIP parameters, same as with Push command in BIP code
                    byte[] connParams = BipCatTP.makeOpenChannelTLVs(ServerSettings.getRamhttpAdminPort(),
                            BipCatTP.OPEN_CHANNEL_TCP_CLIENT_MODE);

                    Utils.BER.appendTLV(this, CONNECTION_PARAMS_TAG, connParams);

                    // Security params
                    byte[] psk = new ByteArrayOutputStream() {
                        {
                            Utils.Pair<byte[], byte[]> r = makePskId(sim);
                            byte[] pskId = r.k;
                            byte[] verIdx = r.l;
                            write(pskId.length);
                            write(pskId);

                            write(verIdx.length); // length of version and index
                            write(verIdx); // Version and key
                        }
                    }.toByteArray();

                    Utils.BER.appendTLV(this, SECURITY_DOMAIN_ADMIN_SESSION_PARAMS_TAG, psk);

                    // Retry policy
                    int xretries = ServerSettings.getRamOpenChannelRetries(); // Same for RAM HTTP
                    if (xretries > 0) {
                        // Retry interval
                        int rinterval = ServerSettings.getRamPushRetryTimeOut();

                        byte[]  retry = new ByteArrayOutputStream() {
                            {
                                write(new byte[]{(byte) ((xretries >> 8) & 0xFF), (byte) (xretries & 0xFF),
                                        // Timer values
                                        TIMER_VALUE_BER_TAG, 0x03, (byte) ((rinterval / 3600) & 0xFF), // Hours
                                        (byte) (((rinterval / 60) % 60) & 0xFF), // Minutes
                                        (byte) ((rinterval % 60) & 0xFF), // Seconds

                                        // Reply SMS, Tag only, no params
                                        RETRY_FAILURE_REPORT_TAG, 0});
                            }
                        }.toByteArray();
                        Utils.BER.appendTLV(this, RETRY_POLICY_PARAMS_TAG, retry);
                    }

                    // HTTP POST params
                    byte[] postParams = new ByteArrayOutputStream() {
                        {
                            // Put in the Agent ID as ICCID
                            String agentID = formatRamHTTPXAdminFrom(sim);
                            Utils.BER.appendTLV(this, AGENT_ID_PARAM_TAG, agentID.getBytes(StandardCharsets.UTF_8));
                            // Put in transaction ID and fetchAFewPending URL
                            String rUri = DISPATCHER_URI;
                            String adminUri = String.format("/%s/%s", rUri, tid);
                            Utils.BER.appendTLV(this, RamHttp.ADMIN_URI_PARAM_TAG, adminUri.getBytes(StandardCharsets.UTF_8));
                        }
                    }.toByteArray();
                    Utils.BER.appendTLV(this, ADMIN_HTTP_POST_PARAMS_TAG, postParams);

                }
            }.toByteArray();


            byte[] triggerParams = new ByteArrayOutputStream() {
                {
                    byte[] securityDomainParameterValues = new ByteArrayOutputStream() {
                        {
                            Utils.BER.appendTLV(this, SECURITY_DOMAIN_PARAMS_TAG, secDomainAdminSessionParams);
                        }
                    }.toByteArray();
                    Utils.BER.appendTLV(this, ADMIN_SESSION_TRIGGER_PARAMS_TAG,securityDomainParameterValues);
                }
            }.toByteArray();

            return triggerParams;
        }

    }

}
