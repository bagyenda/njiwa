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

import io.njiwa.common.*;
import io.njiwa.sr.SmSrTransactionsPeriodicProcessor;
import io.njiwa.sr.model.Eis;
import io.njiwa.sr.model.SecurityDomain;
import io.njiwa.sr.model.SmSrTransaction;
import io.njiwa.sr.ota.Ota;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.ejb.ConcurrencyManagement;
import javax.ejb.ConcurrencyManagementType;
import javax.ejb.Singleton;
import javax.ejb.Startup;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.persistence.EntityManager;
import javax.persistence.LockModeType;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;


/**
 * @brief This is the BIP/CAT_TP implementation
 * @details There are two parts to this module:
 * - The lower layer, which handles the CAT_TP protocol. This is implemented in CatTP class
 * - The upper layer, which handles sending the PUSH SMS to start the BIP/CAT_TP session, and interfaces
 * with the rest of the server.
 * The server calls CatTP.start() at startup (which starts the CAT_TP processor).
 * <p>
 * The server calls CatTP.Connection.getConnectionForMSISDN() to obtain a handle for an existing BIP connection to a subscriber
 * when a Transports.Context object is requested for BIP.
 * <p>
 * To interact with the lower layer, the Transports layer queues events to the lower layers.
 * <p>
 * <p>
 * See below for a discussion on the different layers
 */
@Singleton(name = "Bip")
@Startup
@ConcurrencyManagement(ConcurrencyManagementType.BEAN)
public class BipCatTP extends Transport {

    public static final byte OPEN_CHANNEL_UDP_CLIENT_MODE = 0x01;
    public static final byte OPEN_CHANNEL_TCP_CLIENT_MODE = 0x02;
    private static final int DEFAULT_PUSH_SPI1 = 0x01; // RC Only
    private static final int DEFAULT_PUSH_SPI2 = 0x00;
    private static final int DEFAULT_BIP_BUFFER_LEN = 2048; //!< The default BIP buffer length
    private static byte[] pushCmd1; //!< The  first push command APDU
    private static ScheduledThreadPoolExecutor cleanupProcessor = null;
    private static ExecutorService notificationsProcessor = null;
    // Our peristence container, for our uses.
    // private static PersistenceUtil po = null;
    private static Instance<PersistenceUtility> poTasks = null; //!< We need to get persistence context dynamically for the CAT_TP layer. Hence..
    private static boolean BipStarted = false;

    static {
        // Put the mappers
        BipCatTP bipCatTP = new BipCatTP();
        MessageStatus.statusMap.put(MessageStatus.BipPushConfirmed, bipCatTP);
        MessageStatus.statusMap.put(MessageStatus.BipPushSent, bipCatTP);
        MessageStatus.statusMap.put(MessageStatus.BipWait, bipCatTP);

        TransportType.transportMap.put(TransportType.BIP, bipCatTP);
    }

    @Inject
    Instance<PersistenceUtility> xpoTasks;
    @Inject
    Sms smsT;

    public BipCatTP() {
        unit = "byte(s)";
        // CPI = 0x01; // For BIP that is.
    }

    /**
     * @throws Exception
     * @brief Make the first PUSH command to open the BIP port. Make it using our configuration parameters.
     * This need happen only once, at startup
     */
    private static void makePushCmd1() throws Exception {
        if (pushCmd1 == null) {
            byte[] tlvs = makeOpenChannelTLVs(ServerSettings.getCat_tp_port(), OPEN_CHANNEL_UDP_CLIENT_MODE);
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            os.write(new byte[]{
                    (byte) 0x80,
                    (byte) 0xEC,
                    0x01,
                    0x01,
                    (byte) tlvs.length
            });
            os.write(tlvs);
            pushCmd1 = os.toByteArray();
        }
    }

    /**
     * @param port  - The port to connect to
     * @param proto - The protocol (UDP or TCP)
     * @return The TLV set.
     * @throws Exception
     * @brief Make the Open Channel TLV set for a BIP connection opening.
     */
    public static byte[] makeOpenChannelTLVs(int port, byte proto) throws Exception {
        // Make it.
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        byte[] x;
        try {
            // Write the alpha ID
            x = Charset.alphaConvert(ServerSettings.getBip_title());
            os.write(new byte[]{
                    (byte) 0x05,
                    (byte) (x.length & 0xFF)
            });
            os.write(x, 0, x.length > 255 ? 255 : x.length);
        } catch (Exception ex) {
            Utils.lg.info("Error writing push command: " + ex);
        }

        // Write the GPRS params
        // os.write(Utils.h2b("350702000003000002"));
        os.write(Utils.HEX.h2b("350103")); // Use default bearer confs
        // Write ME buffer  length param
        os.write(new byte[]{
                0x39,
                0x02,
                (byte) ((ServerSettings.getBip_me_buffer_size() >> 8) & 0xFF),
                (byte) (ServerSettings.getBip_me_buffer_size() & 0xFF),
        });

        // Write APN

        byte[] x_apn = ServerSettings.getBip_apn();
        os.write(new byte[]{
                0x47,
                (byte) (x_apn.length & 0xFF),
        });
        os.write(x_apn, 0, x_apn.length > 255 ? 255 : x_apn.length);

        // Empty param. For??
        //  os.write(Utils.h2b("3E00"));

        // Destination port, udp/tcp
        os.write(new byte[]{
                0x3C,
                0x03,
                proto,
                (byte) ((port >> 8) & 0xFF),
                (byte) (port & 0xFF)
        });

        // Destination address, network byte order.
        int addrLen = ServerSettings.getBip_network_interface().length; // IPv6 or 4?
        int addrType = addrLen == 4 ? 0x21 : 0x57;

        os.write(new byte[]{
                0x3E,
                (byte) (addrLen + 1),
                (byte) addrType,

        });
        os.write(ServerSettings.getBip_network_interface());

        return os.toByteArray();
    }

    /**
     * @param msisdn
     * @param tid
     * @return
     * @throws Exception
     * @brief Make the second PUSH APDU command. This must be made on a per-SIM basis since it contains SIM-specific data
     * The connection identifier contains the batch transaction ID and our MSISDN so that we can easily identify
     * the sim card when the incoming connection is received.
     */
    private static byte[] makePushCmd2(String msisdn, long tid) throws Exception {
        Utils.Pair<byte[], Integer> xres = Utils.makePhoneNumber(msisdn.getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream os = new ByteArrayOutputStream();

        // Utils.appendEncodedInteger(os, tid, 8); // Put in 8-byte Transaction id

        Utils.writeLE(os, tid, 8);

        //  ds.writeLong(tid); // Then the trans ID


        os.write(xres.l);
        os.write(xres.k); // Put in number


        byte[] x = os.toByteArray().clone();
        os = new ByteArrayOutputStream();
        // Make the command
        os.write(new byte[]{
                (byte) 0x80, // CLS
                (byte) 0xEC, // INS
                0x01,  // P1
                0x02, // P2
                (byte) (x.length + 7), // P3

                0x3C, // Our CAT TP port. Again?
                0x03,
                0x00,

                (byte) ((ServerSettings.getCat_tp_port() >> 8) & 0xFF),
                (byte) (ServerSettings.getCat_tp_port() & 0xFF)
        });

        os.write(new byte[]{
                0x36,
                (byte) x.length,
        });
        os.write(x);

        return os.toByteArray();
    }

    /**
     * @param in
     * @return
     * @throws Exception
     * @brief When an incoming connection is received, parse it into the transaction ID and the msisdn
     */
    private static Utils.Pair<String, Long> parseIdent(byte[] in) throws Exception {

        // DataInputStream ds = new DataInputStream(new ByteArrayInputStream(in));
        // long tid = Utils.decodeBerInt(in, 8);
        long tid = Utils.readLE(in, 0, 8);

        int n = in[8]; // Get number length

        Utils.Pair<String, Integer> x = Utils.parsePhoneFromSemiOctets(in, n, 9); // Start at position 9.

        return new Utils.Pair<>(x.k, tid);
    }

    /**
     * @param sim
     * @param hasBip
     * @param gotConnection
     * @brief update the subscriber BIP status. This is called if we received a new BIP connection, or if
     * we received an error to a PUSH command (which means the SIM does not understand BIP)
     */
    private static void updateSubscriberStatus(Eis sim, boolean hasBip, boolean gotConnection) {
        Date tnow = Calendar.getInstance().getTime();
        // Update directly? Or hit the DB?
        if (gotConnection)
            sim.setLastBipConnect(tnow);

        // sim.setSkipBip(hasBip ? false : true);
        sim.setNumPendingBipRequests(0);
        sim.setLastBipRequest(tnow);

    }

    /**
     * @brief Returns the euicc, the TAR for basic RFM/BIP Push, the BIP buffer size, and whether BIP is supported
     */
    private static Utils.Quad<Eis, String, Integer, Boolean> getBipInfo(EntityManager em, String msisdn) {
        Eis eis = Eis.findByMsisdn(em, msisdn);
        return getBipInfo(eis);
    }

    private static Utils.Quad<Eis, String, Integer, Boolean> getBipInfo(Eis eis) {

        boolean bipSupport = eis.getCat_tp_support();
        boolean hasDataPlan = eis.getHasDataPlan();

        // If it has BIP support, check when last fetched
        Date lastDplan = eis.getLastDataPlanFetch();
        Date tnow = Calendar.getInstance().getTime();
        long ldiff = lastDplan == null ? ServerSettings.getMax_bip_data_flag_cache_interval() + 100 : (tnow.getTime() - lastDplan.getTime()) / 1000;
        int numOpenRequests = eis.getNumPendingBipRequests();
        if (bipSupport &&
                (!hasDataPlan || ldiff > ServerSettings.getMax_bip_data_flag_cache_interval()))
            // Get the data plan flag
            hasDataPlan = checkAndUpdateSimDataFlag(eis, TransportType.BIP);

        bipSupport = bipSupport && hasDataPlan; // The two go together.
        int bipBufferLen;
        String TAR = "000000";
        if (bipSupport) {
            bipBufferLen = DEFAULT_BIP_BUFFER_LEN;
            // Get the TAR of the SD
            try {
                for (SecurityDomain sd : eis.getSdList())
                    if (sd.getRole() == SecurityDomain.Role.ISDR) {
                        TAR = sd.firstTAR();
                        break;
                    }
            } catch (Exception ex) {
            }
        } else
            bipBufferLen = 0;

        return new Utils.Quad<Eis, String, Integer, Boolean>(eis, TAR, bipBufferLen, bipSupport);
    }

    /**
     * @param connection
     * @throws Exception
     * @brief when a new CAT_TP connection is received, deal with it.
     * This means:
     * - Update the BIP status of the SIM
     * - Immediately send out the batch transaction for which the BIP connection was requested
     */
    private static void handleNewConnection(final CatTP.Connection connection) throws Exception {
        Utils.Pair<String, Long> xres = parseIdent(connection.ident); // Try to parse the identification


        if (xres == null || xres.k == null) {
            connection.requestClosure();
            return;
        }
        final String msisdn = xres.k;
        final long tid = xres.l;
        Utils.lg.info(String.format("BIP [%s]: Incoming connection from [%s] accepted for transaction %s", connection, msisdn, tid));

        // Get the BIP thingies for this guy


        PersistenceUtility po = poTasks.get();
        po.doTransaction(new PersistenceUtility.Runner<Object>() {
            @Override
            public void cleanup(boolean s) {
            }

            @Override
            public Object run(PersistenceUtility po, EntityManager em) throws Exception {
                try {

                    Utils.Quad<Eis, String, Integer, Boolean> x = getBipInfo(em, msisdn);
                    Eis sim = x.k;
                    updateSubscriberStatus(sim, true, true); // We got a new connection, so the sim supports bip.
                    connection.setMsisdn(msisdn);

                    // Send it out immediately.
                    try {

                        SmSrTransaction bt = em.find(SmSrTransaction.class, tid, LockModeType.PESSIMISTIC_WRITE);
                        Utils.lg.info(String.format("BIP: Will attempt to push out transaction [%s] on [%s] via BIP", tid, msisdn));
                        SmSrTransactionsPeriodicProcessor.sendTrans(em, bt);

                    } catch (Exception ex) {
                        Utils.lg.severe(String.format("BIP: Failed to push out trans [%s] on [%s]: %s", tid, msisdn, ex));
                    }
                } catch (Exception ex) {
                    connection.requestClosure(); // Close it.
                }
                return null;
            }
        });
    }

    /**
     * @param conn
     * @param cause
     * @brief When a BIP connection is closed, mark the SIM as able to handle BIP transactions
     */
    private static void handleClosedConnection(final CatTP.Connection conn, int cause) {
        // We know it does BIP, so mark it as such

        PersistenceUtility po = poTasks.get();
        po.doTransaction(new PersistenceUtility.Runner<Object>() {
            @Override
            public void cleanup(boolean s) {
            }

            @Override
            public Object run(PersistenceUtility po, EntityManager em) throws Exception {
                try {
                    Eis sim = Eis.findByMsisdn(em, conn.msisdn);
                    updateSubscriberStatus(sim, true, true);
                } catch (Exception ex) {

                }
                return null;
            }
        });
    }

    private static void handleDataSendRes(CatTP.Connection connection, long tid, boolean success) {
        // Handle fact that data was successfull sent. Perhaps DLR? XXXX

        if (success)
            StatsCollector.recordTransportEvent(TransportType.BIP, PacketType.MT);
    }

    /**
     * @param connection
     * @param data
     * @brief when we receive a full data element (after concatenating incoming segmented packets),
     * we need to pass it to the upper (OTA) layer. This does that.
     */
    private static void handleDataReceived(CatTP.Connection connection, final byte[] data) {
        final String msisdn = connection.msisdn;
        Utils.lg.info(String.format("BIP: Received  %d bytes from %s",
                data != null ? data.length : 0,
                msisdn == null ? "n/a" : msisdn));

        try {
            PersistenceUtility po = poTasks.get();
            po.doTransaction(new PersistenceUtility.Runner<Object>() {
                @Override
                public Object run(PersistenceUtility po, EntityManager em) throws Exception {
                    Ota.receiveMO(data, TransportType.BIP, msisdn, new byte[0], em); // Just call default handler...
                    return null;
                }

                @Override
                public void cleanup(boolean success) {

                }
            });

        } catch (Exception ex) {
            Utils.lg.severe(String.format("BIP: Failed to process received %d bytes from %s: %s", data.length, msisdn == null ? "n/a" : msisdn, ex));
        }
    }

    /**
     * @param catTPCode
     * @param connection
     * @param data
     * @brief All CAT_TP events from the lower layer destined for the upper layer are handled in this method. They are
     * processed asynchronously so that the CAT_TP engine is never slowed down.
     */
    private static void notifyEngine(final CatTP.CatTPCodes catTPCode, final CatTP.Connection connection, final Object data) {
        // Notify upper level of an event

        notificationsProcessor.submit(() -> {
                    try {
                        if (catTPCode == CatTP.CatTPCodes.CAT_TP_NEW_CONN)
                            handleNewConnection(connection);
                        else if (catTPCode == CatTP.CatTPCodes.CAT_TP_DATA_RECVD)
                            handleDataReceived(connection, (byte[]) data);
                        else if (catTPCode == CatTP.CatTPCodes.CAT_TP_CLOSED ||
                                catTPCode == CatTP.CatTPCodes.CAT_TP_CONN_RESET ||
                                catTPCode == CatTP.CatTPCodes.CAT_TP_TIMEOUT)
                            handleClosedConnection(connection, (Integer) data);
                        else if (catTPCode == CatTP.CatTPCodes.CAT_TP_SDU_TOO_LARGE ||
                                catTPCode == CatTP.CatTPCodes.CAT_TP_SEND_OK)
                            handleDataSendRes(connection, (Long) data,
                                    catTPCode == CatTP.CatTPCodes.CAT_TP_SEND_OK ? true : false);
                    } catch (Exception ex) {
                    }
                }
        ); // Just send it off to be processed
    }

    @Override
    public String getName() {
        return "bip";
    }

    //  @Inject
    //  PersistenceUtil xpo;

    @Override
    public TransportType sendMethod() {
        return TransportType.BIP;
    }

    @Override
    public boolean isRunning() {
        return started;
    }

    @Override
    @PostConstruct
    public synchronized void start() {

        if (started)
            return;

        // po = xpo;

        poTasks = xpoTasks; // Get injected one.
        try {
            makePushCmd1();

            // Start the cleanup stuff
            CatTP.start(); // Start the lower layer.
        } catch (Exception ex) {
            Utils.lg.severe(String.format("Error starting BIP: %s", ex));
            ex.printStackTrace();
            return;
        }
        // Start the cleanup threads
        cleanupProcessor = new ScheduledThreadPoolExecutor(ServerSettings.getNumThreads());
        cleanupProcessor.setRemoveOnCancelPolicy(true);
        notificationsProcessor = Executors.newFixedThreadPool(ServerSettings.getNumThreads());

        cleanupProcessor.scheduleAtFixedRate(new Runnable() {
            @Override
            public void run() {
                try {
                    CatTP.Connection.clearIdle(ServerSettings.getBip_idle_timeout());
                } catch (Exception ex) {
                } // Ignore errors. Right?
            }
        }, ServerSettings.getBip_idle_timeout(), ServerSettings.getBip_idle_timeout(), TimeUnit.SECONDS);

        started = BipStarted = true;
    }

    @Override
    @PreDestroy
    public void stop() {


        try {
            CatTP.stop();
            cleanupProcessor.shutdownNow();
        } catch (Exception ex) {
            //  Utils.lg.severe(String.format("Error stopping BIP: %s", ex));
        }
        try {
            notificationsProcessor.shutdown();
        } catch (Exception ex) {
        }
        notificationsProcessor = null;
        cleanupProcessor = null;
        started = BipStarted = false;
    }

    /**
     * @param em
     * @param bt
     * @param oldstatus
     * @param oldmsgStatus
     * @return
     * @brief After the successful handling of a BIP transaction, because BIP is so expensive to setup,
     * we want to push out (immediately) any pending transactions that want BIP, without waiting for the
     * batch transaction dispatcher to get to them. We want to do this because the CAT_TP collection has an idle timeout
     * and will close after a few seconds of no data being transmitted. This does that
     */
    @Override
    public boolean postProcessRecvdTransaction(EntityManager em, SmSrTransaction bt, SmSrTransaction.Status
            oldstatus, MessageStatus oldmsgStatus) {
        if (oldmsgStatus == MessageStatus.BipPushSent)
            return false; // Nothing to do, this is a response to a PUSH

        // Check if we have another one in sequence
        SmSrTransaction x;
        long lasttid = bt.getId();
        try {
            x = bt.findNextAvailableTransaction(em);
        } catch (Exception ex) {
            x = null;
        }
        boolean hasPending = (x != null) || bt.getMoreToFollow(); // Check if upper layer said we close

        if (hasPending)
            return hasPending;

        String msisdn = bt.getMsisdn();
        // Else, push out the first in sequence after us, that was waiting.
        // XXX Shouldn't we push out any that's waiting? Not just the one ahead of us?
        int ntrans = em.createQuery("UPDATE SmSrTransaction  SET nextSend = current_timestamp, status=:sr WHERE eis_id = :m AND id > :i  AND status = :sb")
                .setParameter("m", bt.getEis_id())
                .setParameter("i", bt.getId())
                .setParameter("sr", SmSrTransaction.Status.Ready)
                .setParameter("sb", SmSrTransaction.Status.BipWait)
                .executeUpdate();


        if (ntrans > 0)
            Utils.lg.info(String.format("BipAfterTrans [%s, %d]: Bumped %d transactions to start after BIP response",
                    msisdn, lasttid, ntrans));
        else {
            Utils.lg.info(String.format("BipAfterTrans [%s, %d]: No pending transactions after BIP response. Will close BIP connection.",
                    msisdn, lasttid));
            closeConnection(em, msisdn);
        }

        return hasPending;
    }

    private void closeConnection(EntityManager em, String msisdn) {
        try {
            CatTP.Connection.getConnectionForMSISDN(msisdn).requestClosure();
        } catch (Exception ex) {
        }
    }

    /**
     * @param sim
     * @param transID
     * @return
     * @brief Get a context object. Our context are special here:
     * - They keep track of whether we have an actual connection or not
     * - They keep provide the push message if needed
     * - They modify the OTA parameters (specifically SPI) to ensure PUSH doesn't fail
     */
    @Override
    public Context getContext(Eis sim, Ota.Params p, long transID, int pktSize) {
        // For BIP, first thing we do is determine if the guy supports BIP.
        boolean force = p.forcePush;
        try {
            Utils.Quad<Eis, String, Integer, Boolean> xres = getBipInfo(sim);
            boolean bipSupport = xres.o;
            if (!bipSupport)
                return null;
            CatTP.Connection connection = CatTP.Connection.getConnectionForMSISDN(sim.activeMISDN());
            // Check if max open is passed
            int numOpens = xres.k.getNumPendingBipRequests();
            if (connection == null && numOpens > ServerSettings.getMax_bip_send_requests()) {
                updateSubscriberStatus(xres.k, false, false);
                return null; // No BIP support.
            }
            // Check the connection,
            if (connection != null && connection.isCloseRequested())
                connection = null;
            Context ctx = new Context(xres.k, connection,
                    xres.m,
                    transID, xres.l);

            if (connection == null) {
                // Check whether to force a push
                long tnow = System.currentTimeMillis();
                Date lastOpen = xres.k.getLastBipRequest();
                // Force push if it's been a while, or if we were asked to.
                ctx.forcePush = force ||
                        (lastOpen == null ||
                                tnow - lastOpen.getTime() > numOpens * ServerSettings.getBip_push_retry_timeout() * 1000);

                if (ctx.forcePush) {
                    // Massage the ota parameters
                    ctx.TAR = xres.l;
                    ctx.doPush = true;
                    p.spi1 = DEFAULT_PUSH_SPI1;
                    if ((p.spi2 & 0x01) != 0)
                        p.spi2 = ((p.spi2 & ~3)) & 0xFF | 0x2; // PoR on error only.
                }
            } else {
                ctx.forcePush = false;
                // if ((otaParams.spi2 & 0x03) != 0)
                //     otaParams.spi2 = 0x01; // Basic PoR only
            }
            return ctx; // We will figure out at time of send whether to use Push or not
        } catch (Exception ex) {
            return null; // NO BIP support, upper layer will fall back to SMS
        }
    }

    @Override
    public boolean processTransMessageStatus(EntityManager em, SmSrTransaction bt, boolean success, boolean retry, byte[] data) {
        MessageStatus status = bt.getTransportMessageStatus();

        boolean psent = status == MessageStatus.BipPushSent;

        if (psent) {
            // Update status
            bt.setStatus(success ? SmSrTransaction.Status.BipWait : SmSrTransaction.Status.Ready);
            bt.setSimStatusCode(Utils.HEX.b2H(data));

            bt.setLastupdate(Calendar.getInstance().getTime());
            bt.setTransportMessageStatus(MessageStatus.NA);
            bt.setSimStatusCode(success ? "" : "BIP PUSH Failed");
            if (!success) {
                bt.setNextSend(Calendar.getInstance().getTime()); // Let it go out now. via SMS.
                // And mark the sim as NOT supporting BIP

                em.createQuery("UPDATE Eis  SET lastBipRequest = current_timestamp, numPendingBipRequests = 0 WHERE id = :m")
                        .setParameter("m", bt.getEis_id())
                        .executeUpdate();
            }
        }
        return !psent; // Continue only if this is NOT a response to a PUSH request.
    }

    /**
     * @param em
     * @param context
     * @param text
     * @return
     * @brief Modify the TEXT to send, e.g. if it should become a PUSH message for BIP.
     * XXX Should also return SPI!
     */
    @Override
    public byte[] messageToSend(EntityManager em, Transport.Context context,
                                Ota.Params params,
                                byte[] text) {
        Context ctx = (Context) context;
        // CatTP.Connection connection = ctx.conn;
        if (ctx.usingPush()) {
            params.porOnError = true;
            return ctx.makePushCmd();
        }

        return text;
    }

    @Override
    public int getCPI(Transport.Context context) {
        Context ctx = (Context) context;
        // CatTP.Connection connection = ctx.conn;
        if (ctx.usingPush())
            return -1;
        return 0x01; // If we have a connection, return the BIP CPI
    }

    @Override
    public String getUnit(Transport.Context context) {
        Context ctx = (Context) context;
        // CatTP.Connection connection = ctx.conn;
        if (ctx.usingPush())
            return smsT.getUnit(context);
        return unit;
    }

    @Override
    public boolean hasEnoughBuffer(Transport.Context context, int dlen) {
        Context ctx = (Context) context;
        // CatTP.Connection connection = ctx.conn;
        if (ctx.usingPush())
            return true; // For push, don't even look at buffer size.

        return super.hasEnoughBuffer(context, dlen);
    }

    /**
     * @param em
     * @param context
     * @param msg
     * @param dlr_flags
     * @return
     * @throws Exception
     * @brief Send a message. If the connection is active, simply queue an SDU to the lower layer.
     * Otherwise force a PUSH message (if no connection is live), or cause transaction sending to back off if the
     * outgoing queue is too full.
     */
    @Override
    public Utils.Triple<Integer, MessageStatus, Long> sendMsg(EntityManager em, Transport.Context context, byte[] msg, int dlr_flags) throws Exception {
        Context ctx = (Context) context;

        CatTP.Connection connection = ctx.conn;
        // Must be set by the time we get here. Unless... Right?
        Eis sim = ctx.sim;
        if (connection == null && ctx.forcePush) {
            Date tnow = Calendar.getInstance().getTime();
            // Prepare to push.
            Utils.lg.info(String.format("BIP: Preparing to send PUSH to [%s] for trans [#%s]", ctx.sim.activeMISDN(), ctx.tid));
            sim.setLastBipRequest(tnow);
            sim.setNumPendingBipRequests(sim.getNumPendingBipRequests() + 1);
            // Send it as SMS
            //  Sms smsT = new Sms();
            Utils.Triple<Integer, MessageStatus, Long> xres = smsT.sendMsg(em, context, msg, DLR_DELIVERED_TO_PHONE); // Message passed to us is already in coded form.
            MessageStatus status = xres.l == MessageStatus.Sent ? MessageStatus.BipPushSent : MessageStatus.BipWait;
            long nextt = (1 + sim.getNumPendingBipRequests()) * ServerSettings.getBip_push_retry_timeout(); // When to next try...
            return new Utils.Triple<>(xres.k, status, nextt);
        }
        if (connection == null || connection.isCloseRequested() ||
                connection.outgoingSDUs.size() > ServerSettings.getMax_bip_send_queue()) { // Buffer is full, or connection is closing, or no connection since we last came here
            // Must wait a little
            return new Utils.Triple<>(0, MessageStatus.BipWait, ServerSettings.getBip_push_retry_timeout());
        }

        // We have a BIP connection, queue the message and go
        connection.queueSDU(msg.clone(), ctx.tid);

        return new Utils.Triple<>(msg.length, MessageStatus.Sent, -1L);
    }

    /**
     * @summary The CAT TP Engine.
     * @details The CAT TP engine is basically a simple finite state machine.
     * A Connection is identified by the UDP socket. Each connection starts out in the LISTEN state
     * (i.e. when no device/SIM has connected). Each packet received is treated as an event which may or may not
     * cause a state transition to a new state. In addition, entering a new state or processing an event
     * may start a timer. When the timer expires it triggers a new event, which is then received and processed against
     * the connection, which results in a new transition. And so on...
     * <p>
     * The details are to be found below
     */
    private static class CatTP {
        public static final int CAT_TP_WIN_SIZE = 10; //!< The default window size for CAT TP
        public static final int CAT_TP_DEFAULT_MAX_RTT = 60; //!< The default maximum (expected) round trip time
        public static final int CAT_TP_DEFAULT_MIN_RTT = 2; //!< The default minimum
        public static final int CAT_TP_DEFAULT_RETRIES = 10; //!< Default maximum CAT TP retries
        public static final int SND_INITIAL_SQ_NB = 1; //!< Initial sending packet sequence number
        public static final int CAT_TP_DEFAULT_DATA_TIMEOUT = 20 * 60; //!< Default data timeout in seconds
        public static final int CAT_TP_MAX_PDU = 200; //!< Maximum Packet size in butes
        public static final int CAT_TP_MIN_PDU = 0x17; //!< Minimum Packet size (of course this is the size of the header
        public static final int CAT_TP_MAX_SDU = 0xFFFF; //!< Maximum (non-segmented) data packet size
        public static final int SYN_SENT_STATE = 1; //!< SYN_SENT state: Because we want to use them for OR-ing, state numbers must be multiples or 2
        public static final int SYN_RCVD_STATE = 2; //!< The Recvd state flag
        public static final int OPEN_STATE = 4; //!< Open state flag
        public static final int CLOSE_WAIT_STATE = 8; //!< Close wait state flag
        public static final int LISTEN_STATE = 16; //!< Listen state flag
        public static final int DEAD_STATE = 32; //!< Dead state flag
        private static final int MAX_STATE = DEAD_STATE; //!< Largest state constant

        private static final List<StateTransitionRule>[] transitionRules; //!< These the state transition rules Indexed by state ID.
        private static DatagramSocket socket; //!< The server socket
        private static boolean stopIt = false;
        private static Thread socketThread = null; //!< Socket listener thread
        private static BlockingQueue<Event> eventsList = new LinkedBlockingQueue<Event>(); //!<  The global event queue
        private static Thread eventDispatcher = null; //!< The event dispatcher/processor
        private static ExecutorService eventProcessor = null; //!< Event processor thread pool

        static {
            // Here we initiliase the CAT TP Finite State Machine
            // These are the special, shared actions:

            //! This is a connection reset action/rule: It is used when the connection likely needs to be closed.
            final StateTransitionRule conn_reset_f = new StateTransitionRule() {
                @Override
                public int action(Event evt) throws Exception {
                    int code = Packet.RSTParams.NORMAL;
                    CatTPCodes res;
                    int seqNum;

                    // Cancel keep alive timer
                    Timers.cancel(KeepAliveEvent.class, 0); // Cancel the keep alive.

                    if (evt instanceof RetransmitEvent)
                        seqNum = ((RetransmitEvent) evt).pdu.sequenceNumber + 1;
                    else if (evt instanceof CloseConnectionEvent)
                        seqNum = evt.connection.snd_nxt_seq_nb;
                    else
                        seqNum = evt.connection.rcv_cur_seq_nb;

                    // Cancel all waitin retransmissions
                    for (int i = evt.connection.snd_una_pdu_seq_nb; i < seqNum; i++)
                        Timers.cancel(RetransmitEvent.class, i);
                    if (evt instanceof RetransmitEvent ||
                            evt instanceof KeepAliveEvent ||
                            evt instanceof CloseConnectionEvent) {
                        // Send a packet
                        Packet pkt = new Packet(Packet.RST_PDU,
                                evt.connection.cat_tp_src_port,
                                evt.connection.cat_tp_dst_port,
                                0,
                                seqNum, 0, 0);
                        pkt.setRstparams(evt instanceof RetransmitEvent ? Packet.RSTParams.MAX_RETRIES_EXCEEDED : Packet.RSTParams.NORMAL);
                        pkt.send(evt.connection.destAddr);
                        res = evt instanceof CloseConnectionEvent ? CatTPCodes.CAT_TP_CLOSED : CatTPCodes.CAT_TP_TIMEOUT;
                    } else
                        res = CatTPCodes.CAT_TP_CONN_RESET;

                    // Notify above
                    notifyEngine(res, evt.connection, code);

                    // Set a timer to close it finally
                    Timers.put(new CloseConnectionEvent(evt.connection), seqNum, evt.connection.rto, eventsList);
                    return CLOSE_WAIT_STATE;
                }
            };

            final StateTransitionRule reject_sdu_f = new StateTransitionRule() {
                @Override
                public int action(Event evt) throws Exception {
                    SendSDUEvent sevt = (SendSDUEvent) evt;
                    Connection connection = evt.connection;
                    notifyEngine(connection != null & connection.currentState == OPEN_STATE ?
                            CatTPCodes.CAT_TP_SDU_TOO_LARGE : CatTPCodes.CAT_TP_CLOSED, connection, sevt.tid);
                    return -1;
                }
            }; //!< This is a generic SDU rejection state transition: Whenever we receive an packet to send but can't send it,we need to throw it away and inform sender

            /**
             * @brief This is a list of all the state transitions by event type and conditions to satisfy
             */
            StateTransitionRule[] _xrules = new StateTransitionRule[]{
                    // Listen state thingie
                    new StateTransitionRule() {
                        {
                            states = LISTEN_STATE;
                            eventClass = RecvPduEvent.class;
                            name = "listen";
                        }


                        @Override
                        public int action(Event evt) throws Exception {
                            // Check the type of event and act
                            RecvPduEvent rpdu = (RecvPduEvent) evt;
                            Packet pkt = rpdu.pdu;
                            Packet out = null;
                            int new_state = -1;
                            if (pkt.isSYN_PDU() && pkt.getSynparams().maxPDU < CAT_TP_MIN_PDU) {
                                // As per spec, drop the packet
                                out = new Packet(Packet.RST_PDU | Packet.ACK_PDU,
                                        pkt.destPort, pkt.srcPort, 0, pkt.sequenceNumber + 1, 0, 0);
                                out.setRstparams(Packet.RSTParams.CONNECT_FAILED_ILLEGAL_PARAM);
                            } else if (pkt.isSYN_PDU()) {
                                // We are good. Make a new connection
                                evt.connection = new Connection(rpdu.addr.getAddress(),
                                        rpdu.addr.getPort(),
                                        pkt.getSynparams().identification, pkt.sequenceNumber,
                                        pkt.getSynparams().maxPDU,
                                        pkt.getSynparams().maxSDU,
                                        pkt.srcPort, // Switch them
                                        pkt.destPort);

                                // Make the ack packaet
                                out = new Packet(Packet.ACK_PDU | Packet.SYN_PDU,
                                        pkt.destPort, pkt.srcPort,
                                        0,
                                        evt.connection.snd_nxt_seq_nb,
                                        pkt.sequenceNumber, CAT_TP_WIN_SIZE);
                                // Then send back identifier
                                out.setSynparams(evt.connection.snd_pdu_size_max, evt.connection.snd_sdu_size_max,
                                        new byte[0]); // Empty IDent as per Sec 9.2.2 of ETSI 102 226
                                // evt.connection.ident);
                            } else
                                Utils.lg.severe(String.format("CAT_TP: Discarding PDU [%s] received in LISTEN State", pkt));

                            if (evt.connection != null) {
                                // Start keep-alive
                                Timers.put(new KeepAliveEvent(evt.connection), 0, CAT_TP_DEFAULT_DATA_TIMEOUT, eventsList);
                                evt.connection.currentState = new_state = SYN_RCVD_STATE;
                            }

                            if (out != null) {
                                if (evt.connection != null)
                                    evt.connection.sendPacket(out); // Send it with retry.
                                else
                                    out.send(rpdu.addr.getAddress(), rpdu.addr.getPort());
                            }
                            return -1;
                        }

                    },

                    // Syn Received, PDU received
                    new StateTransitionRule() {
                        {
                            eventClass = RecvPduEvent.class;
                            states = SYN_RCVD_STATE;
                            name = "syn_recvd";
                        }

                        @Override
                        public boolean predicate(Event evt) {
                            RecvPduEvent pdu = (RecvPduEvent) evt;
                            Packet pkt = pdu.pdu;
                            return !(evt.connection.rcv_ini_seq_nb < pkt.sequenceNumber &&
                                    pkt.sequenceNumber <= evt.connection.rcv_cur_seq_nb + CAT_TP_WIN_SIZE); // Pg 33 of ETSI 127...
                        }

                        @Override
                        public int action(Event evt) throws Exception {
                            RecvPduEvent pdu = (RecvPduEvent) evt;
                            Packet recvd = pdu.pdu;
                            Packet pkt = new Packet(Packet.ACK_PDU,
                                    recvd.destPort,
                                    recvd.srcPort,
                                    0,
                                    evt.connection.snd_nxt_seq_nb,
                                    evt.connection.rcv_cur_seq_nb,
                                    CAT_TP_WIN_SIZE);
                            pkt.send(pdu.addr.getAddress(), pdu.addr.getPort()); // No retry
                            return -1;
                        }
                    },

                    // Syn or EACK received in syn received state, drop connection (pg 40)
                    // XXX Note that order of these conditions matters
                    new StateTransitionRule() {
                        @Override
                        public boolean predicate(Event evt) {
                            RecvPduEvent pdu = (RecvPduEvent) evt;
                            return (evt.connection.rcv_ini_seq_nb < pdu.pdu.sequenceNumber &&
                                    pdu.pdu.sequenceNumber <= evt.connection.rcv_cur_seq_nb + CAT_TP_WIN_SIZE) &&
                                    (pdu.pdu.isRST_PDU());
                        }

                        @Override
                        public int action(Event evt) throws Exception {
                            RecvPduEvent pdu = (RecvPduEvent) evt;
                            Packet pkt = pdu.pdu;

                            Packet out = new Packet(pkt.isACK_PDU() || pkt.isEACK_PDU() ? Packet.RST_PDU : (Packet.RST_PDU | Packet.ACK_PDU),
                                    pkt.destPort, pkt.srcPort,
                                    0,
                                    pkt.isEACK_PDU() || pkt.isACK_PDU() ? pkt.ackNumber + 1 : 0,
                                    pkt.isACK_PDU() ? 0 : pkt.sequenceNumber, 0
                            );
                            out.setRstparams(Packet.RSTParams.CONNECT_FAILED_ILLEGAL_PARAM);
                            out.send(pdu.addr.getAddress(), pdu.addr.getPort());

                            notifyEngine(CatTPCodes.CAT_TP_CLOSED, evt.connection, CatTPCodes.CAT_TP_CONN_INVALID_PACKET);
                            evt.connection.clear(); // Clear this thingie

                            return -1;
                        }

                        {
                            states = SYN_RCVD_STATE;
                            eventClass = RecvPduEvent.class;
                            name = "syn_rcvd_syn_or_eaj_close_conn";
                        }
                    },

                    // Received ACK in Syn state
                    new StateTransitionRule() {
                        @Override
                        public boolean predicate(Event evt) {
                            RecvPduEvent recvPduEvent = (RecvPduEvent) evt;
                            Packet pdu = recvPduEvent.pdu;
                            return (evt.connection.rcv_ini_seq_nb < pdu.sequenceNumber &&
                                    pdu.sequenceNumber <= evt.connection.rcv_cur_seq_nb + CAT_TP_WIN_SIZE) &&
                                    !pdu.isSYN_PDU() && // Page 40
                                    !pdu.isEACK_PDU() &&
                                    pdu.isACK_PDU() &&
                                    (pdu.ackNumber == SND_INITIAL_SQ_NB); // Receipt of SYN_ACK, deal with it
                        }

                        @Override
                        public int action(Event evt) throws Exception {
                            int new_state = -1;
                            RecvPduEvent recvPduEvent = (RecvPduEvent) evt;
                            Packet pdu = recvPduEvent.pdu;
                            Event revt = Timers.cancel(RetransmitEvent.class, pdu.ackNumber); // Cancel the retransmit event for this

                            // Set window size, since it is an ACK
                            evt.connection.snd_win_size = pdu.winSize;
                            if (revt != null)
                                evt.connection.recomputeRto(revt);
                            // Else do nothing since retransmit was already sent.
                            if (evt.connection.snd_una_pdu_seq_nb <= pdu.ackNumber &&
                                    pdu.ackNumber < evt.connection.snd_nxt_seq_nb)
                                evt.connection.snd_una_pdu_seq_nb = pdu.ackNumber + 1; // We have this many acknowledged

                            if (pdu.dataLen == 0 && !pdu.isNUL_PDU()) {
                                // Connection has been opened by the ACK to the SYN+ACK
                                new_state = OPEN_STATE;
                                notifyEngine(CatTPCodes.CAT_TP_NEW_CONN, evt.connection, null);
                            } else {
                                // Error, send a generic ACK and close it

                                Packet out = new Packet(Packet.ACK_PDU, evt.connection.cat_tp_src_port,
                                        evt.connection.cat_tp_dst_port, 0,
                                        evt.connection.snd_nxt_seq_nb,
                                        evt.connection.rcv_cur_seq_nb,
                                        CAT_TP_WIN_SIZE);
                                out.send(evt.connection.destAddr);

                                notifyEngine(CatTPCodes.CAT_TP_CLOSED, evt.connection, Packet.RSTParams.UNEXPECTED_PDU);
                                evt.connection.clear(); // Drop the connection
                            }

                            return new_state;

                        }

                        {
                            states = SYN_RCVD_STATE;
                            eventClass = RecvPduEvent.class;
                            name = "syn_rcvd_ack";
                        }
                    },

                    //! Retransmission
                    new StateTransitionRule() {

                        @Override
                        public int action(Event evt) throws Exception {
                            RetransmitEvent revt = (RetransmitEvent) evt;

                            if (revt.retries > ServerSettings.getMaxRetries()) // Reset it
                                try {
                                    return conn_reset_f.action(evt);
                                } catch (Exception ex) {
                                    Utils.lg.severe(String.format("CAT_TP Engine [%s]: Cancel retry failed on %s: %s", evt.connection, revt.pdu, ex));
                                }
                            else // Retry
                                evt.connection.sendWithRetry(revt.pdu, revt.retries, revt.timeSent);
                            return -1;
                        }

                        {
                            states = SYN_RCVD_STATE | SYN_SENT_STATE | OPEN_STATE;
                            eventClass = RetransmitEvent.class;
                            name = "retransmit_pkt";
                        }
                    },

                    //! Close a connection when waiting, also generic connection reset
                    new StateTransitionRule() {
                        // No check.

                        @Override
                        public int action(Event evt) throws Exception {
                            Utils.lg.info(String.format("Closing connection [%s] after close_wait timeout ",
                                    evt.connection != null ? evt.connection : "n/a"));
                            try {
                                evt.connection.clear();
                            } catch (Exception ex) {
                            }
                            return -1;
                        }

                        {
                            states = CLOSE_WAIT_STATE;
                            eventClass = CloseConnectionEvent.class;
                            name = "close_wait_reset";
                        }
                    },

                    //! A close connection from the upper levels
                    new StateTransitionRule() {
                        @Override
                        public int action(Event evt) throws Exception {
                            return conn_reset_f.action(evt);
                        }

                        {
                            states = OPEN_STATE | SYN_RCVD_STATE;
                            eventClass = CloseConnectionEvent.class;
                            name = "close_wait_close";
                        }
                    },

                    new StateTransitionRule() {
                        {
                            states = OPEN_STATE;
                            eventClass = KeepAliveEvent.class;
                            name = "open_keep_alive";
                        }

                        @Override
                        public boolean predicate(Event evt) {
                            long t = System.currentTimeMillis();
                            return t - evt.connection.last_rcv_data > CAT_TP_DEFAULT_DATA_TIMEOUT + 60; // Close connection on no data
                        }

                        @Override
                        public int action(Event evt) throws Exception {
                            return conn_reset_f.action(evt);
                        }
                    },

                    //! Restart Keep-alive
                    new StateTransitionRule() {
                        {
                            states = OPEN_STATE;
                            eventClass = KeepAliveEvent.class;
                            name = "restart_keep_alive";
                        }

                        @Override
                        public boolean predicate(Event evt) {
                            long t = System.currentTimeMillis();
                            return t - evt.connection.last_rcv_data < CAT_TP_DEFAULT_DATA_TIMEOUT; // new keep alive
                        }

                        @Override
                        public int action(Event evt) throws Exception {
                            Timers.put(new KeepAliveEvent(evt.connection), 0, CAT_TP_DEFAULT_DATA_TIMEOUT, eventsList);
                            return -1;
                        }
                    },
                    //! Discard outside window
                    new StateTransitionRule() {
                        {
                            states = OPEN_STATE;
                            eventClass = RecvPduEvent.class;
                            name = "discard_pkt_outside_window";
                        }

                        @Override
                        public boolean predicate(Event evt) {
                            RecvPduEvent revt = (RecvPduEvent) evt;
                            return !(evt.connection.rcv_cur_seq_nb < revt.pdu.sequenceNumber &&
                                    revt.pdu.sequenceNumber <= evt.connection.rcv_cur_seq_nb + CAT_TP_WIN_SIZE + 1);
                        }

                        @Override
                        public int action(Event evt) throws Exception {
                            Packet ack = new Packet(Packet.ACK_PDU, evt.connection.cat_tp_src_port,
                                    evt.connection.cat_tp_dst_port, 0,
                                    evt.connection.snd_nxt_seq_nb, evt.connection.rcv_cur_seq_nb, CAT_TP_WIN_SIZE);
                            ack.send(evt.connection.destAddr);
                            return -1;
                        }

                    },
                    //! Packet within window but is a RST packet
                    new StateTransitionRule() {
                        {
                            states = OPEN_STATE;
                            eventClass = RecvPduEvent.class;
                            name = "rst_packet_in_open_state";
                        }

                        @Override
                        public boolean predicate(Event evt) {
                            RecvPduEvent revt = (RecvPduEvent) evt;
                            Packet pdu = revt.pdu;
                            return (evt.connection.rcv_cur_seq_nb < pdu.sequenceNumber &&
                                    pdu.sequenceNumber <= evt.connection.rcv_cur_seq_nb + CAT_TP_WIN_SIZE + 1) &&
                                    pdu.isRST_PDU();
                        }

                        @Override
                        public int action(Event evt) throws Exception {
                            return conn_reset_f.action(evt);
                        }
                    },
                    //! Discard SYN
                    new StateTransitionRule() {
                        {
                            states = OPEN_STATE;
                            eventClass = RecvPduEvent.class;
                            name = "syn_packet_in_open_state";
                        }

                        @Override
                        public boolean predicate(Event evt) {
                            RecvPduEvent revt = (RecvPduEvent) evt;
                            Packet pdu = revt.pdu;
                            return (evt.connection.rcv_cur_seq_nb < pdu.sequenceNumber &&
                                    pdu.sequenceNumber <= evt.connection.rcv_cur_seq_nb + CAT_TP_WIN_SIZE + 1) &&
                                    pdu.isSYN_PDU();
                        }

                        @Override
                        public int action(Event evt) throws Exception {
                            RecvPduEvent revt = (RecvPduEvent) evt;
                            Packet pdu = revt.pdu;
                            Packet out = new Packet(pdu.isACK_PDU() ? Packet.RST_PDU :
                                    Packet.ACK_PDU | Packet.RST_PDU,
                                    evt.connection.cat_tp_src_port, evt.connection.cat_tp_dst_port,
                                    0, pdu.sequenceNumber + 1, pdu.sequenceNumber, 0);
                            out.setRstparams(Packet.RSTParams.CONNECT_FAILED_ILLEGAL_PARAM);

                            out.send(evt.connection.destAddr);

                            notifyEngine(CatTPCodes.CAT_TP_CLOSED, evt.connection, Packet.RSTParams.CONNECT_FAILED_ILLEGAL_PARAM);
                            // Close the connection

                            Utils.lg.info(String.format("CAT TP [%s]: Connection closed (reason=%s]", evt.connection, Packet.RSTParams.CONNECT_FAILED_ILLEGAL_PARAM));
                            try {
                                evt.connection.clear();
                                // evt.connection.currentState = DEAD_STATE;
                            } catch (Exception ex) {
                            }
                            return -1;
                        }
                    },

                    //! Received within window but has no SYN or ACK or EACK or NULL or RST and has no data, discard*
                    new StateTransitionRule() {
                        {
                            states = OPEN_STATE;
                            eventClass = RecvPduEvent.class;
                            name = "packet_no_data";
                        }

                        @Override
                        public boolean predicate(Event evt) {
                            RecvPduEvent revt = (RecvPduEvent) evt;
                            Packet pdu = revt.pdu;
                            return (evt.connection.rcv_cur_seq_nb < pdu.sequenceNumber &&
                                    pdu.sequenceNumber <= evt.connection.rcv_cur_seq_nb + CAT_TP_WIN_SIZE + 1) &&
                                    !pdu.isOneOf(Packet.SYN_PDU | Packet.ACK_PDU | Packet.EACK_PDU | Packet.NUL_PDU | Packet.RST_PDU) &&
                                    (pdu.dataLen == 0);
                        }

                        // No action, do default
                    },

                    //! Receive valid pdu, in sequence
                    new StateTransitionRule() {
                        {
                            states = OPEN_STATE;
                            eventClass = RecvPduEvent.class;
                            name = "packet_recv";
                        }

                        @Override
                        public boolean predicate(Event evt) {
                            RecvPduEvent revt = (RecvPduEvent) evt;
                            Packet pdu = revt.pdu;
                            return (evt.connection.rcv_cur_seq_nb < pdu.sequenceNumber &&
                                    pdu.sequenceNumber <= evt.connection.rcv_cur_seq_nb + CAT_TP_WIN_SIZE + 1) &&
                                    !pdu.isOneOf(Packet.SYN_PDU | Packet.RST_PDU);
                        }

                        @Override
                        public int action(Event evt) throws Exception {
                            RecvPduEvent revt = (RecvPduEvent) evt;
                            Packet pdu = revt.pdu;
                            Connection conn = evt.connection;
                            // From pg 35/36 of spec,
                            if (pdu.isACK_PDU()) {
                                if (conn.snd_una_pdu_seq_nb - 1 == pdu.ackNumber) {
                                    if (conn.snd_win_size < pdu.winSize)
                                        conn.snd_sdu_size_max = pdu.winSize; // Change of window size
                                } else if (conn.snd_una_pdu_seq_nb <= pdu.ackNumber &&
                                        pdu.ackNumber < conn.snd_nxt_seq_nb) {

                                    int old_una_sq = conn.snd_una_pdu_seq_nb;
                                    conn.snd_una_pdu_seq_nb = pdu.ackNumber + 1;
                                    conn.snd_win_size = pdu.winSize;

                                    // Cancel all timers
                                    for (int i = old_una_sq; i <= pdu.ackNumber; i++) {
                                        Event e = Timers.cancel(RetransmitEvent.class, i);
                                        if (e != null)
                                            conn.recomputeRto(e);
                                    }
                                }
                            }

                            if (pdu.isEACK_PDU()) {
                                Packet.EACKParams eparams = pdu.getEackparams();
                                // Cancel all acknowledged retransmit timers
                                for (int i = 0; i < eparams.seqNums.length; i++) {
                                    int xid = eparams.seqNums[i];
                                    Event e = Timers.cancel(RetransmitEvent.class, xid);
                                    if (e != null)
                                        conn.recomputeRto(e);
                                }
                            }
                            // A packet without data which is not a null pkt, just send more data
                            if (pdu.dataLen == 0 && !pdu.isNUL_PDU()) {
                                conn.sendPacket(null);
                                return -1;
                            }

                            if (pdu.dataLen > 0 && // Received a data packet outside (right edge) of our flow window, drop it.
                                    pdu.sequenceNumber > conn.rcv_cur_seq_nb + CAT_TP_WIN_SIZE) {
                                conn.sendPacket(new Packet(Packet.ACK_PDU,
                                        pdu.destPort,
                                        pdu.srcPort,
                                        0,
                                        conn.snd_nxt_seq_nb,
                                        conn.rcv_cur_seq_nb,
                                        CAT_TP_WIN_SIZE));
                                return -1; // Remain open
                            }
                            if (pdu.dataLen > 0 ||
                                    pdu.isNUL_PDU()) {
                                int idx = pdu.sequenceNumber - (conn.rcv_cur_seq_nb + 1);
                                try {
                                    if (conn.rcv_out_of_seq_pdu[idx] == null)
                                        conn.rcv_out_of_seq_pdu[idx] = pdu; // If received not in sequence, store
                                } catch (Exception ex) {

                                }
                            }
                            // If we received packet in sequence: i.e. one greater than last one, then we do build.
                            if (pdu.sequenceNumber == conn.rcv_cur_seq_nb + 1) {
                                // Find largest one
                                int i, j;
                                for (i = 0; i < CAT_TP_WIN_SIZE; i++)
                                    if (conn.rcv_out_of_seq_pdu[i] == null)
                                        break;
                                    else if (conn.rcv_out_of_seq_pdu[i].sequenceNumber > conn.rcv_cur_seq_nb)
                                        conn.rcv_cur_seq_nb = conn.rcv_out_of_seq_pdu[i].sequenceNumber; // Find largest in sequence
                                for (i = 0, j = 0; i < CAT_TP_WIN_SIZE; i++)
                                    if (conn.rcv_out_of_seq_pdu[i] != null &&
                                            conn.rcv_out_of_seq_pdu[i].sequenceNumber <= conn.rcv_cur_seq_nb) {
                                        if (conn.rcv_out_of_seq_pdu[i].dataLen > 0) // Get the data
                                            conn.receivedPkts.add(conn.rcv_out_of_seq_pdu[i]);
                                        conn.rcv_out_of_seq_pdu[i] = null;
                                    } else if (conn.rcv_out_of_seq_pdu[i] != null) {
                                        Packet x = conn.rcv_out_of_seq_pdu[i];
                                        conn.rcv_out_of_seq_pdu[i] = null; // Clear it.
                                        conn.rcv_out_of_seq_pdu[j++] = x;
                                    }
                            }

                            // Count out-of-order PDUs received to decide whether to use ACK or EACK
                            int n = 0;
                            for (int i = 0; i < CAT_TP_WIN_SIZE; i++)
                                if (conn.rcv_out_of_seq_pdu[i] != null)
                                    n++;
                            // try to fit it in EACK, else an ACK. ACK all the packets that we have not ACKed
                            while (n > 0 &&
                                    Packet.staticHeaderLen + (n * 2) > conn.snd_pdu_size_max)
                                n--;
                            Packet res = null;
                            if (n == 0)
                                res = new Packet(Packet.ACK_PDU, pdu.destPort, pdu.srcPort, 0,
                                        conn.snd_nxt_seq_nb,
                                        conn.rcv_cur_seq_nb,
                                        CAT_TP_WIN_SIZE);
                            else {
                                res = new Packet(Packet.EACK_PDU,
                                        pdu.destPort, pdu.srcPort, 0,
                                        conn.snd_nxt_seq_nb,
                                        conn.rcv_cur_seq_nb,
                                        CAT_TP_WIN_SIZE);
                                // Make the EACK
                                List<Integer> l = new ArrayList<Integer>();
                                for (int i = 0; i < CAT_TP_WIN_SIZE; i++)
                                    if (conn.rcv_out_of_seq_pdu[i] != null)
                                        l.add(conn.rcv_out_of_seq_pdu[i].sequenceNumber);
                                int[] seqNums = new int[l.size()];
                                for (int i = 0; i < seqNums.length; i++)
                                    seqNums[i] = l.get(i);
                                res.setEackparams(seqNums);

                            }
                            conn.sendPacket(res);

                            boolean found;
                            // Search for complete SDUs and notify upper layer
                            do {
                                int i;
                                Packet xpkt;
                                ByteArrayOutputStream sdu = new ByteArrayOutputStream();
                                found = false;
                                for (i = 0; i < conn.receivedPkts.size(); i++)
                                    if ((xpkt = conn.receivedPkts.get(i)) != null) {
                                        sdu.write(xpkt.data);
                                        if (!pdu.isSEG_PDU())
                                            break; // End of contiguous stuff
                                    }
                                if (i < conn.receivedPkts.size()) {
                                    // WE got a full SDU above
                                    notifyEngine(CatTPCodes.CAT_TP_DATA_RECVD, conn, sdu.toByteArray());

                                    while (i-- >= 0) // Clear recd data
                                        conn.receivedPkts.remove(0); // Take off stuff.
                                }
                            } while (found);
                            return -1;
                        }
                    },

                    //! Discard send SDU requests when not open
                    new StateTransitionRule() {
                        {
                            states = SYN_RCVD_STATE | CLOSE_WAIT_STATE | LISTEN_STATE;
                            eventClass = SendSDUEvent.class;
                            name = "reject_sdu_when_not_open";
                        }

                        @Override
                        public int action(Event evt) throws Exception {
                            return reject_sdu_f.action(evt);
                        }
                    },

                    //! Reject too large
                    new StateTransitionRule() {
                        {
                            states = OPEN_STATE;
                            eventClass = SendSDUEvent.class;
                            name = "reject_sdu_too_large";
                        }

                        @Override
                        public boolean predicate(Event evt) {
                            SendSDUEvent sevt = (SendSDUEvent) evt;
                            int size = sevt.data.available();

                            return size > evt.connection.snd_sdu_size_max;
                        }

                        @Override
                        public int action(Event evt) throws Exception {
                            // Reject the package
                            return reject_sdu_f.action(evt);
                        }
                    },

                    //! Queue an SDU
                    new StateTransitionRule() {
                        {
                            states = OPEN_STATE;
                            eventClass = SendSDUEvent.class;
                            name = "queue_sdu";
                        }

                        @Override
                        public boolean predicate(Event evt) {
                            SendSDUEvent sevt = (SendSDUEvent) evt;
                            int size = sevt.data.available();

                            return size > 0 && size <= evt.connection.snd_sdu_size_max;
                        }

                        @Override
                        public int action(Event evt) throws Exception {
                            SendSDUEvent sevt = (SendSDUEvent) evt;
                            Utils.Pair<ByteArrayInputStream, Long> x = new Utils.Pair<ByteArrayInputStream, Long>(sevt.data, sevt.tid);
                            evt.connection.outgoingSDUs.add(x);

                            // Push out packets that might be waiting
                            evt.connection.sendPacket(null);

                            return -1;
                        }
                    }
            };

            // Now munge them.
            transitionRules = new List[MAX_STATE + 1];
            for (int i = 1; i <= MAX_STATE; i *= 2)
                transitionRules[i] = new ArrayList<StateTransitionRule>();

            for (int i = 0; i < _xrules.length; i++) {
                StateTransitionRule sr = _xrules[i];
                int states = sr.states;
                // Now, for all states, do the needful
                for (int j = 1; j <= MAX_STATE; j *= 2)
                    if ((j & states) != 0)
                        transitionRules[j].add(sr);
            }
        }

        private static String stateToString(int state) {
            switch (state) {
                case SYN_SENT_STATE:
                    return "SYNSENT";
                case SYN_RCVD_STATE:
                    return "SYNRECVD";
                case OPEN_STATE:
                    return "OPEN";
                case CLOSE_WAIT_STATE:
                    return "CLOSEWAIT";
                case LISTEN_STATE:
                    return "LISTEN";
                case DEAD_STATE:
                    return "DEAD";
            }
            return "n/a";
        }

        /**
         * @param evt
         * @brief When an event is received, This function passes through the list of transition rules for the current
         * state of the connection, finds the first matching one (by calling the predicate() method) and runs the attendant
         * method. The method may result in a new state transition of course.
         */
        private static void processEvent(Event evt) {
            // Run through the event thingie and do the needful

            // Connection connection = evt.connection;
            int currentState = evt.connection == null ? LISTEN_STATE : evt.connection.currentState;

            // Do some book-keeping
            if (evt.connection != null && (evt instanceof RecvPduEvent)) {
                evt.connection.last_rcv_pkt = evt.timeStamp;
                RecvPduEvent pduEvent = (RecvPduEvent) evt;
                Packet pkt = pduEvent.pdu;

                if (pkt.dataLen > 0 ||
                        pkt.isSYN_PDU())
                    evt.connection.last_rcv_data = evt.timeStamp;
            }
            // Now look for the transition rules and apply

            for (StateTransitionRule rule : transitionRules[currentState])
                if (rule.eventClass.isInstance(evt) && rule.predicate(evt))
                    try {
                        int new_state = rule.action(evt);
                        int xnew_state = new_state >= 0 ? new_state : evt.connection != null ? evt.connection.currentState : -1;

                        Utils.lg.info(String.format("Cat_TP event processed [rule: %s, State %s->%s, evt: %s]", rule,
                                stateToString(currentState),
                                stateToString(xnew_state),
                                evt));

                        if (new_state >= 0 && evt.connection != null) // Re-set the state.
                            evt.connection.currentState = new_state;
                        return; // Done
                    } catch (Exception ex) {
                        Utils.lg.severe(String.format("CAT_TP Exception in processing event [%s]: %s", evt, ex));
                    }
            Utils.lg.info(String.format("Cat_TP discarding unexpected event [%s], on connection [%s] ", evt, evt.connection != null ? evt.connection : "n/a"));
        }

        /**
         * Start the CAT_TP engine: Start the event processor threads, start the timers, open the CAT_TP port, set up the port listener.
         *
         * @throws Exception
         */
        public static synchronized void start() throws Exception {

            if (socket != null)
                return;
            stopIt = false;
            socket = new DatagramSocket(ServerSettings.getCat_tp_port());

            // Initialise the event Processors and event dispatcher
            eventProcessor = Executors.newFixedThreadPool(ServerSettings.getNumThreads()); // Make executors
            eventDispatcher = new Thread(new Runnable() {
                @Override
                public void run() {
                    Utils.lg.info("CAT_TP Event dispatcher starting up...");
                    while (!stopIt)
                        try {
                            final Event evt = eventsList.take();
                            Utils.lg.info(String.format("CAT_TP Event [%s]", evt));
                            // We got it. Now, dispatch it.
                            eventProcessor.execute(new Runnable() {
                                Event xevt = evt;

                                @Override
                                public void run() {
                                    // Call the state transition processor.
                                    processEvent(xevt);
                                }
                            });
                        } catch (Exception ex) {
                            Utils.lg.severe(String.format("Event dispatcher loop exception: %s", ex));
                        }
                    Utils.lg.info("CAT_TP Event dispatcher stopped...");
                }
            });


            // The CATP socket receiver.
            socketThread = new Thread(() -> {
                byte[] data = new byte[1024];
                Utils.lg.info("CAT_TP UDP Socket server starting up on port [" + ServerSettings.getCat_tp_port() + "]...");
                while (!stopIt)
                    try {
                        DatagramPacket pkt = new DatagramPacket(data, data.length);
                        socket.receive(pkt);

                        byte[] x = pkt.getData();
                        int len = pkt.getLength();
                        int offset = pkt.getOffset();
                        // Copy it
                        byte[] rcvdData = Arrays.copyOfRange(x, offset, offset + len);
                        // Utils.lg.info(String.format("CAT_TP received %d bytes from [%s:%s]: %s",
                        //         len,
                        //         pkt.getAddress(), pkt.getPort(), Utils.b2H(rcvdData)));
                        Packet pdu;
                        try {
                            pdu = Packet.parse(rcvdData); // Gets it and checks checksum, or fails
                        } catch (Exception ex) {
                            pdu = null;
                        }
                        Utils.lg.info(Packet.dumpPacket(pdu, true, (InetSocketAddress) pkt.getSocketAddress(), rcvdData));
                        Connection conn = Connection.getConnection(pkt);
                        RecvPduEvent pevt = new RecvPduEvent(pkt.getAddress(), pkt.getPort(), pdu, conn);
                        eventsList.add(pevt); // Dump it on the queue.
                    } catch (Exception ex) {
                        Utils.lg.severe(String.format("CAT_TP Recv error: %s", ex));
                    }
                Utils.lg.info("CAT_TP Socket server stopped.");
            });

            socketThread.start();
            eventDispatcher.start();

        }

        /**
         * Stop the CAT_TP engine
         *
         * @throws Exception
         */
        public static synchronized void stop() throws Exception {
            if (socket == null)
                return;

            stopIt = true;


            try {
                socket.close();
                socketThread.interrupt();
            } catch (Exception ex) {

            }
            // Kill the event processors
            Timers.cancelAll(); // Kill all timers.
            try {
                eventDispatcher.interrupt();
            } catch (Exception ex) {
            }
            try {
                eventProcessor.shutdownNow();
            } catch (Exception ex) {
            }
            Connection.clearAll();
            eventDispatcher = null;
            eventProcessor = null;
            socket = null;
        }

        public enum CatTPCodes {
            CAT_TP_SEND_OK,
            CAT_TP_TIMEOUT,
            CAT_TP_SDU_TOO_LARGE,
            CAT_TP_NOT_OPEN,
            CAT_TP_CLOSED,
            CAT_TP_CONN_RESET,
            CAT_TP_CONN_INVALID_PACKET,

            CAT_TP_NEW_CONN,
            CAT_TP_DATA_RECVD
        }


        /**
         * @brief This is the base Event class. An event may be a PDU reception event, a
         * timer expiration, a retransmission event, etc
         */
        private static class Event {
            // Base class for an event
            public Connection connection; //!< The connection (or null) against which event is fired.
            public long timeStamp = System.currentTimeMillis(); //!< When the event was created or received.

            // public Event() {}
            public Event(Connection conn) {
                connection = conn;
            }

            @Override
            public String toString() {
                return "GenericEvent";
            }
        }

        /**
         * A PDU received results in this kind of event being queued
         */
        private static class RecvPduEvent extends Event {
            public InetSocketAddress addr; //!< The socket on which it was received
            public Packet pdu; //!< The received PDU

            public RecvPduEvent(InetAddress fromAddress, int fromPort, Packet pdu, Connection conn) {
                super(conn);
                addr = new InetSocketAddress(fromAddress, fromPort);
                this.pdu = pdu;
                //connection = conn;
            }

            @Override
            public String toString() {
                return String.format("ReceivePDUEvent [%s:%s] [%s]",
                        addr == null ? "n/a" : addr.getAddress(),
                        addr == null ? "" : addr.getPort(),
                        pdu == null ? "n/a" : pdu);
            }
        }

        /**
         * @brief A PDU retransmission event
         */
        private static class RetransmitEvent extends Event {
            public int retries; //!< Number of retries so
            public long timeSent; //!< in milliseconds since epoch
            public Packet pdu; //!< The PDU to retransmit when the timer expires
            public long created = System.currentTimeMillis(); //!< When the retransmit was created

            public RetransmitEvent(int retries, long timeSent, Packet pdu, Connection conn) {
                super(conn);
                this.retries = retries;
                this.timeSent = timeSent;
                this.pdu = pdu;

            }

            @Override
            public String toString() {
                return String.format("RetransimitEvent [%s retries]", retries);
            }
        }

        /**
         * A request to send data, from the upper level
         */
        private static class SendSDUEvent extends Event {
            public ByteArrayInputStream data; //!< The data to send
            public long tid; //!< The upper level ID

            public SendSDUEvent(byte[] sdu, long tid, Connection conn) {
                super(conn);
                data = new ByteArrayInputStream(sdu.clone()); // Get a copy and keep it.
                this.tid = tid;

            }

            @Override
            public String toString() {
                return String.format("SendSDUEvent [%s bytes]", data.available());
            }
        }

        /**
         * A keep alive event, which is queued after a timeout
         */
        public static class KeepAliveEvent extends Event {
            public long timestamp = System.currentTimeMillis(); //!< Keep alive timestamp in seconds

            public KeepAliveEvent(Connection conn) {
                super(conn);
            }

            @Override
            public String toString() {
                return String.format("KeepAliveEvent [%s tstamp]", timestamp);
            }
        }

        /**
         * A connection closure event, usually queued when the connection has been idle for a while,
         * or on request from the upper layer
         */
        public static class CloseConnectionEvent extends Event {
            public long timestamp = System.currentTimeMillis(); //!< When close was requested

            public CloseConnectionEvent(Connection conn) {
                super(conn);
            }

            @Override
            public String toString() {
                return "CloseConnEvent";
            }

        }

        /**
         * This is the CAT_TP connection representation
         */
        private static class Connection {
            private static final double ALPHA = 0.5; //!< This is a smoothing parameter from RFC 793
            private static final double BETA = 1.3; //!< Also smoothing parameter from RFC 793
            private static Map<String, Connection> activeConnections = new ConcurrentHashMap<String, Connection>(); //!< List of active connections
            private static Map<String, Connection> msisdnMap = new ConcurrentHashMap<String, Connection>(); //!< List of active Indexed by msisdn, points to same...
            // Represents a connection.
            public int currentState = LISTEN_STATE; //!< Current connection state
            public byte[] ident; //!< The connection Identifier as received
            public int SrcPort, DestPort; //!< Cat TP params
            public String msisdn; //!< The MSISDN
            public long srtt = 0; //!< Smoothed round trip for a packet, starts out as default
            public long rto = CAT_TP_DEFAULT_MAX_RTT; //!< Round trip time
            public int snd_nxt_seq_nb = SND_INITIAL_SQ_NB; /*!< Next PDU sequence number when sending */
            public int snd_una_pdu_seq_nb;  /*!< Oldest unacknowledged PDU that was sent. */
            public int snd_pdu_size_max, snd_sdu_size_max;  /*!< Largest PDU/SDU that can be sent. */
            public int snd_win_size;       /*!< receiver's CAT TP window size. */
            public int rcv_cur_seq_nb; /*!< Last received in-sequence PDU */
            public int rcv_ini_seq_nb; /*!< First sequence received. */
            public long last_rcv_pkt = 0; //!< When last packet was received
            public long last_rcv_data = 0; //!< When last data was received.
            public Packet[] rcv_out_of_seq_pdu = new Packet[CAT_TP_WIN_SIZE]; /*!< List of out-of-sequence received PDUs  as Packet pointers. Indexed as offset from rcv_cur_seq_nb + 1 */
            public int cat_tp_dst_port = 0; //!< The destination port in the CAT_TP packet
            public int cat_tp_src_port = 0; //!< The source port in the CAT_TP packet
            InetSocketAddress destAddr; //!< The destination address
            List<Packet> receivedPkts = new ArrayList<Packet>(); //!< Received packets until we have an SDU
            Queue<Utils.Pair<ByteArrayInputStream, Long>> outgoingSDUs = new LinkedList<Utils.Pair<ByteArrayInputStream, Long>>(); //!< Outgoing SDUs on this connection
            private boolean closeRequested = false;
            private long lastt = System.currentTimeMillis(); //!< When last active from the perspective of the upper layer.

            /**
             * @param address
             * @param port
             * @param ident
             * @param seqNum
             * @param maxPDU
             * @param maxSDU
             * @param dstPort
             * @param srcPort
             * @brief Make a new CAT_TP connection object with the given parameters
             */
            public Connection(InetAddress address, int port, byte[] ident, int seqNum, int maxPDU, int maxSDU, int dstPort, int srcPort) {
                this.destAddr = new InetSocketAddress(address, port);
                this.ident = ident;
                this.rcv_ini_seq_nb = this.rcv_cur_seq_nb = seqNum;
                this.snd_pdu_size_max = maxPDU;
                this.snd_sdu_size_max = maxSDU;

                this.cat_tp_dst_port = dstPort;
                this.cat_tp_src_port = srcPort;


                // Put a new connection into our pool. *after it has been initiliased fully of course *
                activeConnections.put(getID(), this);
            }

            /**
             * Compute a new smoothed round trip time given the current smoothed round trip time and the last round trip time seen
             * This is from RFC 793
             *
             * @param srtt
             * @param rtt
             * @return
             */
            private static long SRTT(long srtt, long rtt) {
                return (long) (ALPHA * srtt + (1 - ALPHA) * rtt);
            }

            /**
             * Compute the round trip time.
             *
             * @param srtt
             * @param rtt
             * @return
             */
            private static long RTO(long srtt, long rtt) {
                return (long) Math.min((double) CAT_TP_DEFAULT_MAX_RTT, Math.max((double) CAT_TP_DEFAULT_MIN_RTT,
                        (BETA * SRTT(srtt, rtt))));
            }

            private static String getConnectionID(DatagramPacket pkt) {


                return getConnectionID(pkt.getAddress().toString(), pkt.getPort());
            }

            public static String getConnectionID(String host, int port) {
                return String.format("%s:%s", host, port);
            }

            public static Connection getConnection(DatagramPacket pkt) {
                String cID = getConnectionID(pkt);

                return activeConnections.get(cID);
            }

            public static Connection getConnectionForMSISDN(String msisdn) {
                return msisdnMap.get(msisdn);
            }

            public static Connection getConnectionForID(String cID) {
                return activeConnections.get(cID);
            }

            public static synchronized void clearAll() {
                Set<String> l = activeConnections.keySet();
                for (String k : l)
                    try {
                        Connection c = activeConnections.remove(k);
                        c.clear();
                    } catch (Exception ex) {
                    }
                try {
                    msisdnMap.clear();

                } catch (Exception ex) {
                }
            }

            public static synchronized void clearIdle(long idleTimeout) {
                Set<String> l = activeConnections.keySet();
                for (String k : l)
                    try {
                        long tnow = System.currentTimeMillis();
                        Connection c = activeConnections.get(k);
                        if (tnow - c.lastt > idleTimeout) {
                            Utils.lg.info(String.format("Going to request closure of idle connection: %s", c));
                            c.requestClosure();
                        }
                    } catch (Exception ex) {
                    }

            }

            /**
             * Recompute the round trip time from a retransmission event.
             *
             * @param evt
             */
            public synchronized void recomputeRto(Event evt) {
                try {
                    RetransmitEvent revt = (RetransmitEvent) evt; // Might fail, in which case, ignore

                    long rtt = System.currentTimeMillis() - revt.timeSent;
                    if (rtt > 0) {
                        srtt = srtt > 0 ? SRTT(srtt, rtt) : rtt; // First time, we set round trip to what we got. Next time we smooth it.
                        rto = RTO(srtt, rtt);
                        Utils.lg.info(String.format("CatTP conn [%s] new RTO=>%s", this, rto));
                    }

                } catch (Exception ex) {
                }
            }

            /**
             * @param sdu
             * @param tid
             * @brief Queue an SDU (i.e. MT data) onto the connection. This is simply turned into an SDU Event
             * which the state machine will proces accordingly
             */
            public void queueSDU(byte[] sdu, long tid) {
                eventsList.add(new SendSDUEvent(sdu, tid, this));
            }

            /**
             * @param pkt
             * @param numRetries
             * @param lastt
             * @throws Exception
             * @brief Send a packet and start a timer to queue a retransmit event when it expires.
             */
            public void sendWithRetry(Packet pkt, int numRetries, long lastt) throws Exception {
                pkt.send(destAddr.getAddress(), destAddr.getPort()); // Send it
                // Then optionally queue a retry

                if (pkt.isSYN_PDU() || pkt.isNUL_PDU() || (pkt.dataLen > 0)) {
                    RetransmitEvent re = new RetransmitEvent(numRetries + 1, lastt, pkt, this);
                    Timers.put(re, pkt.sequenceNumber, rto, eventsList); // Queue a retry
                }
            }

            /**
             * Get an SDU from the list of outgoing data packets
             *
             * @param max_size
             * @return
             */
            private synchronized Utils.Pair<byte[], Long> getOutgoingData(int max_size) {
                // Try to get as much outgoing data from our list as possible
                synchronized (outgoingSDUs) {
                    if (outgoingSDUs.size() == 0)
                        return null;
                    try {
                        Utils.Pair<ByteArrayInputStream, Long> x = outgoingSDUs.peek();
                        ByteArrayInputStream in = x.k;
                        int dsize = max_size > in.available() ? in.available() : max_size;
                        byte[] out = new byte[dsize];
                        in.read(out);


                        Long xout;
                        if (in.available() <= 0) {
                            outgoingSDUs.remove();
                            xout = x.l;
                        } else
                            xout = null;
                        Utils.lg.severe(String.format("CAT_TP [%s]: Got  outgoing data [size=%s] ", this, dsize));
                        return new Utils.Pair<>(out, xout);

                    } catch (Exception ex) {
                        Utils.lg.severe(String.format("Hive off outgoing [%s, size=%s], failed: %s ", this, max_size, ex));
                    }
                }
                return null;
            }

            /**
             * @param pkt the packet
             * @brief Send a packet on the connection.
             * @details Send a packet if the CAT TP sending window is still valid.
             * Also send any additional SDUs that need to go out, still obeying the windowing rules of CAT TP
             */
            public synchronized void sendPacket(Packet pkt) {

                do {
                    int dsize;
                    boolean finalPduInSDU = false;
                    Long tid = null;
                    // Send the one passed to us, optionally appending some data to it.
                    if (pkt != null &&
                            (pkt.isEACK_PDU() || pkt.isACK_PDU()) &&
                            snd_nxt_seq_nb < snd_una_pdu_seq_nb + snd_win_size &&
                            (dsize = snd_pdu_size_max - pkt.headerLen) > 0) {
                        // We can add data to this packet, so do so
                        Utils.Pair<byte[], Long> xdata = getOutgoingData(dsize);
                        if (xdata != null) {
                            pkt.setData(xdata.k);
                            finalPduInSDU = xdata.l != null;
                            if (finalPduInSDU) {
                                tid = xdata.l;
                                Utils.lg.info("Cat_TP Write: Full SDU sent");
                            } else
                                pkt.descriptor |= Packet.SEG_PDU; // Indicate segmentation at play
                        }
                    }

                    if (pkt != null) {
                        boolean synOrNul = pkt.isNUL_PDU() || pkt.isSYN_PDU();
                        boolean hasData = pkt.dataLen > 0;

                        try {
                            sendWithRetry(pkt, 0, System.currentTimeMillis());
                            if (hasData || synOrNul)
                                snd_nxt_seq_nb++;
                            if (hasData && finalPduInSDU)
                                notifyEngine(CatTPCodes.CAT_TP_SEND_OK, this, tid); // Notify upper level that we sent ok.
                        } catch (Exception ex) {
                            Utils.lg.severe(String.format("Error sending packet [%s] on [%s]: %s", pkt, this));
                        }
                        pkt = null;
                    }

                    // Try to send more
                    if (snd_nxt_seq_nb < snd_una_pdu_seq_nb + snd_win_size &&
                            outgoingSDUs.size() > 0) { // We have more data and we can send it, so send it
                        pkt = new Packet(Packet.ACK_PDU,
                                cat_tp_src_port,
                                cat_tp_dst_port,
                                0,
                                snd_nxt_seq_nb,
                                rcv_cur_seq_nb,
                                CAT_TP_WIN_SIZE);
                    }

                } while (pkt != null);

            }

            @Override
            public String toString() {
                String id = getID();

                return String.format("Conn [net: %s, msisdn: %s, state: %s]", id, msisdn == null ? "n/a" : msisdn, stateToString(currentState));
            }

            public String getID() {
                return getConnectionID(destAddr.getAddress().toString(), destAddr.getPort());
            }

            public synchronized void setMsisdn(String msisdn) {
                this.msisdn = msisdn;
                msisdnMap.put(msisdn, this);
            }

            public synchronized void clear() {


                try {
                    activeConnections.remove(getID());
                } catch (Exception ex) {
                }

                try {
                    msisdnMap.remove(msisdn);
                } catch (Exception ex) {

                }
                currentState = DEAD_STATE;
            }

            public void requestClosure() {
                if (isCloseRequested())
                    return; // Don't do it twice.
                setCloseRequested(true);
                Utils.lg.info(String.format("Cat_TP connection closure requested for [%s]", this));
                CloseConnectionEvent evt = new CloseConnectionEvent(this);
                eventsList.add(evt); // Queue an event.
            }

            public synchronized boolean isCloseRequested() {
                return closeRequested;
            }

            public synchronized void setCloseRequested(boolean closeRequested) {
                this.closeRequested = closeRequested;
            }
        }

        /**
         * @brief The State Transition rule
         * <p>
         * A finite state transition rule is defined by this class.
         */
        private static class StateTransitionRule {

            public int states; //!< The states in which this  rule applies
            public Class<? extends Event> eventClass; //!< The event class that triggers this transition
            public String name = "";

            /**
             * @param evt
             * @return
             * @brief Given an event, perform some computation to decide if
             * the state transition should be done. This may involve checking CAT TP window sizes, etc
             */
            public boolean predicate(Event evt) {
                return true; // Default is do not check
            }

            /**
             * @param evt
             * @return
             * @throws Exception
             * @brief Perform some actions before the state transition
             */
            public int action(Event evt) throws Exception {
                // Over-ridden by subclasses
                return -1; // Do nothing so we can leave as default when not needed.
            }

            @Override
            public String toString() {
                return name;
            }
        }

        /**
         * Timers module: A timer is an event that should be fired after a certain number of seconds has elapsed
         * This is used say for packet retransmission.
         * A timer can also be cancelled at any time by the caller, in which case the event it represents is returned.
         * Each timer is also identified by an integer ID
         */
        private static class Timers {
            private static ScheduledThreadPoolExecutor schPool = new ScheduledThreadPoolExecutor(4);
            private static Map<String, Utils.Quad<Event, Long, ScheduledFuture, Long>> activeTimers = new ConcurrentHashMap<>();

            static {
                schPool.setRemoveOnCancelPolicy(true); // Clear when removed.
            }

            /**
             * Makea timer ID string from the event class and the ID
             *
             * @param cls
             * @param id
             * @return
             */
            private static String timerId(Class<? extends Event> cls, long id) {
                return String.format("%s-%s", cls.getName(), id);
            }

            /**
             * Add an event to the timer queue. This will cause the event to be queued for processing after 'seconds' given.
             *
             * @param event
             * @param id
             * @param seconds
             * @param eventList
             */
            public static void put(final Event event,
                                   final long id, long seconds,
                                   final Collection<Event> eventList) {

                final long tnow = System.currentTimeMillis();
                Utils.lg.info(String.format("CAT_TP future/timer event request for <%s[%s]>", event, id));
                // Schedule the task, keep track of thingies
                ScheduledFuture f = schPool.schedule(new Runnable() {
                    Event xevent = event;
                    long xid = id;

                    String cname = xevent.toString();

                    public void run() {
                        long elapsed = System.currentTimeMillis() - tnow;
                        Utils.lg.info(String.format("CAT_TP Timer <%s [%s]> elapsed after %s seconds", cname, xid, elapsed / 1000));
                        try {
                            activeTimers.remove(timerId(xevent.getClass(), xid));
                        } catch (Exception ex) {
                        }
                        try {
                            eventList.add(xevent); // Queue it upwards.
                        } catch (Exception ex) {
                        }
                    }
                }, seconds, TimeUnit.SECONDS);

                activeTimers.put(timerId(event.getClass(), id), new Utils.Quad<>(event, tnow, f, id));
            }

            /**
             * Cancel a timer event given the Id.
             *
             * @param eventClass
             * @param id
             * @param immediate
             * @return
             */
            public static Event cancel(Class<? extends Event> eventClass, long id, boolean immediate) {
                return cancel(timerId(eventClass, id), immediate);
            }

            /**
             * Cancel a timer event given the ID and the event class.
             *
             * @param eventClass
             * @param id
             * @return
             */
            public static Event cancel(Class<? extends Event> eventClass, long id) {
                return cancel(eventClass, id, false);
            }

            /**
             * Cancel a timer given the ID representation.
             * Remove it from the list of timers, get the event scheduled and cancel it.
             *
             * @param id
             * @param immediate
             * @return
             */
            private static Event cancel(String id, boolean immediate) {
                try {
                    Utils.Quad<Event, Long, ScheduledFuture, Long> xf =
                            activeTimers.remove(id);
                    ScheduledFuture f = xf.m;
                    long startedAt = xf.l;
                    long xid = xf.o;
                    Event evt = xf.k;
                    f.cancel(immediate);
                    long tnow = System.currentTimeMillis();
                    long tspent = tnow - startedAt;
                    Utils.lg.info(String.format("CAT_TP Timer cancelled <%s [%s]>, after %s seconds", evt, xid, tspent / 1000));
                    return xf.k;
                } catch (Exception ex) {
                }
                return null;
            }

            /**
             * Shut down all pending timers.
             */
            public static void cancelAll() {
                Set<String> keylist = activeTimers.keySet();
                for (String key : keylist)
                    try {
                        cancel(key, true);
                    } catch (Exception ex) {
                    }
            }
        }

        /**
         * A CAT TP Packet, received or to be sent. The different packet types
         * are defined in the CAT TP specification. This is a straight representation of them.
         */
        private static class Packet {

            public static final int NUL_PDU = (1 << 3);
            public static final int RST_PDU = (1 << 4);
            public static final int EACK_PDU = (1 << 5);
            public static final int ACK_PDU = (1 << 6);
            public static final int SYN_PDU = (1 << 7);
            public static final int SEG_PDU = (1 << 2);
            private static final int staticHeaderLen = 0x12; // As per secion 5.6.2 of ETSI TS 102 127.
            // Represents a packet.
            public int descriptor = 0; // The first octet.
            public int headerLen = staticHeaderLen;
            public int srcPort, destPort, sequenceNumber, ackNumber, winSize;
            private EACKParams eackparams = null;
            private SYNParams synparams = null;
            private RSTParams rstparams = null;
            private int dataLen = 0;
            // The variable stuff
            private byte[] extra_headers = new byte[0];
            private byte[] data = new byte[0];

            public Packet() {
            }

            /**
             * @param descriptor
             * @param srcPort
             * @param destPort
             * @param dataLen
             * @param sequenceNumber
             * @param ackNumber
             * @param winSize
             * @brief Create a packet with the given packet header fields
             */
            public Packet(int descriptor, int srcPort,
                          int destPort, int dataLen,
                          int sequenceNumber,
                          int ackNumber, int winSize) {

                this.descriptor = descriptor;
                this.dataLen = dataLen;

                this.srcPort = srcPort;
                this.destPort = destPort;
                this.sequenceNumber = sequenceNumber;
                this.ackNumber = ackNumber;
                this.winSize = winSize;
            }

            public Packet(int descriptor, int srcPort,
                          int destPort, int dataLen,
                          int sequenceNumber,
                          int ackNumber, int winSize, byte[] data) {
                this(descriptor, srcPort, destPort, dataLen, sequenceNumber, ackNumber, winSize);
                this.setData(data);
            }

            public static String dumpPacket(Packet pkt, boolean incoming, InetSocketAddress socketAddress, byte[] raw) {
                String hst = "";
                try {
                    hst = String.format("(%s:%s)", socketAddress.getAddress(), socketAddress.getPort());
                } catch (Exception ex) {
                }
                String out = String.format(incoming ? " <==%s== %s" : " ==%s==> %s", hst, pkt != null ? pkt : "n/a");

                if (raw != null)
                    out += String.format(" [raw [%s bytes]: %s]", raw.length, Utils.HEX.b2H(raw));
                return out;
            }

            public static String dumpPacket(Packet pkt, boolean incoming, InetSocketAddress socketAddress) {
                return dumpPacket(pkt, incoming, socketAddress);
            }

            /**
             * @param in
             * @return
             * @throws Exception
             * @brief Read the packet from the input
             */
            public static Packet parse(byte[] in) throws Exception {
                if (checksum(in, in.length) != 0)
                    throw new Exception("Invalid checksum");
                // Read the header
                Packet pkt = new Packet();

                DataInputStream ds = new DataInputStream(new ByteArrayInputStream(in));
                pkt.descriptor = ds.readByte();
                int rfu = ds.readShort(); // Ignore rfu
                pkt.headerLen = ds.readByte();
                pkt.srcPort = ds.readShort();
                pkt.destPort = ds.readShort();
                pkt.dataLen = ds.readShort();
                pkt.sequenceNumber = ds.readShort();
                pkt.ackNumber = ds.readShort();
                pkt.winSize = ds.readShort();
                short cksum = ds.readShort(); // Ignore

                int eLen = pkt.headerLen - staticHeaderLen;
                if (eLen > 0) {
                    pkt.setExtra_headers(new byte[eLen]);
                    ds.read(pkt.getExtra_headers());
                }

                if (pkt.dataLen > 0) {
                    pkt.setData(new byte[pkt.dataLen]);
                    ds.read(pkt.getData());
                }

                return pkt;
            }

            /**
             * @param in
             * @param count
             * @return
             * @brief Compute the checksum of a packet
             */
            private static int checksum(byte[] in, int count) {
                long crc16 = 0;
                int i = 0;
                while (count > 1) {
                    // Get two bytes at a time
                    int y = (in[i] & 0xFF) | ((in[i + 1] & 0xFF) << 8);
                    long x = crc16 + y;

                    crc16 = (x & 0xFFFFL) + ((x & 0xFFFFFFFFL) >> 16);
                    crc16 &= 0xFFFFFFFFL;
                    i += 2;
                    count -= 2;
                }

                if (count > 0) {
                    long x = crc16 + (in[i] & 0xFF);
                    crc16 = (x & 0xFFFFL) + ((x & 0xFFFFFFFFL) >> 16);
                    crc16 &= 0xFFFFFFFFL;
                }
                return (int) ((~crc16) & 0xFFFFL); // Mask off top bits
            }


            public boolean isNUL_PDU() {
                return (descriptor & NUL_PDU) != 0;
            }

            public boolean isRST_PDU() {
                return (descriptor & RST_PDU) != 0;
            }

            public boolean isEACK_PDU() {
                return (descriptor & EACK_PDU) != 0;
            }

            public boolean isACK_PDU() {
                return (descriptor & ACK_PDU) != 0;
            }

            public boolean isSYN_PDU() {
                return (descriptor & SYN_PDU) != 0;
            }

            public boolean isSEG_PDU() {
                return (descriptor & SEG_PDU) != 0;
            }

            public boolean isOneOf(int codes) {
                return (descriptor & codes) != 0;
            }

            @Override
            public String toString() {
                String type = "";
                String out = "";

                // Make the type string
                String sep = "";
                if (isNUL_PDU()) {
                    type += sep + "NUL";
                    sep = " ";
                }
                if (isRST_PDU()) {
                    type += sep + "RST";
                    sep = " ";
                }
                if (isEACK_PDU()) {
                    type += sep + "EACK";
                    sep = " ";
                }
                if (isACK_PDU()) {
                    type += sep + "ACK";
                    sep = " ";
                }
                if (isSYN_PDU()) {
                    type += sep + "SYN";
                    sep = " ";
                }
                if (isSEG_PDU()) {
                    type += sep + "SEG";
                    sep = " ";
                }

                out = String.format("[%s:seq=%04d ack=%04d:%d->%d:hlen=%d,dlen=%d:win=%d",
                        type, sequenceNumber, ackNumber,
                        srcPort,
                        destPort,
                        headerLen, dataLen,
                        winSize);
                if (isSYN_PDU())
                    out += ":" + getSynparams();
                if (isEACK_PDU())
                    out += ":" + getEackparams();
                if (isRST_PDU())
                    out += ":" + getRstparams();
                if (dataLen > 0 && data != null)
                    out += ":data=" + Utils.HEX.b2H(data);

                return out + "]";
            }

            public SYNParams getSynparams() {
                if (synparams == null && isSYN_PDU())
                    synparams = new SYNParams(); // Initialise
                return synparams;
            }

            public void setSynparams(int maxPDU, int maxSDU, byte[] ident) {
                SYNParams synparams = new SYNParams(maxPDU, maxSDU, ident);
                descriptor |= SYN_PDU;
                this.synparams = synparams;

                // Set variable stuff
                ByteArrayOutputStream os = new ByteArrayOutputStream();
                DataOutputStream ds = new DataOutputStream(os);

                try {
                    ds.writeShort(synparams.maxPDU);
                    ds.writeShort(synparams.maxSDU);
                    ds.write(synparams.identification.length); // Put out the length,
                    ds.write(synparams.identification); // Then the ID
                    ds.flush();
                    setExtra_headers(os.toByteArray());
                } catch (Exception ex) {
                }

                headerLen = staticHeaderLen + 2 * 2 + 1 + synparams.identification.length; // Length of syn PDU header
            }

            public EACKParams getEackparams() {
                if (eackparams == null && isEACK_PDU())
                    eackparams = new EACKParams();
                return eackparams;
            }

            // Ignore RFU

            public void setEackparams(int[] seqNums) {
                setEackparams(seqNums, null);
            }

            public void setEackparams(int[] seqNums, byte[] xdata) {
                descriptor |= EACK_PDU;
                EACKParams eackparams = new EACKParams(seqNums); // Make it.
                this.eackparams = eackparams;
                // Re-generate PDU.
                ByteArrayOutputStream os = new ByteArrayOutputStream();
                DataOutputStream ds = new DataOutputStream(os);

                try {
                    for (int i = 0; i < eackparams.seqNums.length; i++)
                        ds.writeShort(eackparams.seqNums[i]);
                    ds.flush();
                    setExtra_headers(os.toByteArray());
                } catch (Exception ex) {
                }
                headerLen = staticHeaderLen + 2 * eackparams.seqNums.length; // New header length...
                data = xdata != null ? xdata : new byte[0];
                dataLen = data.length;
            }

            public RSTParams getRstparams() {
                if (rstparams == null && isRST_PDU())
                    rstparams = new RSTParams();
                return rstparams;
            }

            public void setRstparams(int code) {
                descriptor |= RST_PDU;
                RSTParams rstparams = new RSTParams(code);
                headerLen = 1 + staticHeaderLen; // Reset header size
                this.rstparams = rstparams;
                setExtra_headers(new byte[]{(byte) rstparams.reason});
            }

            public byte[] getExtra_headers() {
                return extra_headers;
            }

            public void setExtra_headers(byte[] extra_headers) {
                this.extra_headers = extra_headers;
            }

            public byte[] getData() {
                return data;
            }

            public void setData(byte[] data) {
                this.data = data != null ? data : new byte[0];

                dataLen = this.data.length;
            }

            public int getVersion() {
                return descriptor & 0x03;
            }

            public byte[] toBytes() throws Exception {
                ByteArrayOutputStream os = new ByteArrayOutputStream();
                DataOutputStream ds = new DataOutputStream(os);

                // Write the thingies in order

                ds.writeByte(descriptor);
                ds.writeShort(0); // RFU
                ds.writeByte(headerLen);
                ds.writeShort(srcPort);
                ds.writeShort(destPort);
                ds.writeShort(dataLen);
                ds.writeShort(sequenceNumber);
                ds.writeShort(ackNumber);
                ds.writeShort(winSize);
                ds.writeShort(0); // Put checksum in as zero to start...
                if (getExtra_headers() != null && getExtra_headers().length > 0)
                    ds.write(getExtra_headers());

                if (getData() != null && getData().length > 0)
                    ds.write(getData());

                ds.flush();
                // Now make checksum
                byte[] out = os.toByteArray();
                int cksum = checksum(out, out.length);

                // Now insert the checksum
                final int CKSUM_OFFSET = 16;
                out[CKSUM_OFFSET] = (byte) (cksum & 0xFF);
                out[CKSUM_OFFSET + 1] = (byte) ((cksum >> 8) & 0xFF);

                return out;
            }

            public void send(InetSocketAddress addr) throws Exception {
                send(addr.getAddress(), addr.getPort());
            }

            public void send(InetAddress address, int port) throws Exception {
                byte[] data = toBytes();

                socket.send(new DatagramPacket(data, data.length, address, port));

                Utils.lg.info(dumpPacket(this, false, new InetSocketAddress(address, port), data));
                // Utils.lg.info(String.format("Sent raw packets [%s]", Utils.b2H(data)));
            }

            /**
             * Represent special SYN Params
             */
            public class SYNParams {
                public int maxPDU;
                public int maxSDU;
                public byte[] identification;

                public SYNParams() {

                    // Examine variable area, get the params out
                    try {
                        DataInputStream ds = new DataInputStream(new ByteArrayInputStream(getExtra_headers()));
                        maxPDU = ds.readShort(); // Get max PDU/SDU
                        maxSDU = ds.readShort(); // Get max PDU/SDU
                        int idLen = ds.readByte(); // Get the length of the ID
                        identification = new byte[idLen];
                        ds.read(identification);
                    } catch (Exception ex) {
                    }
                }

                public SYNParams(int maxPDU, int maxSDU, byte[] ident) {
                    this.maxPDU = maxPDU;
                    this.maxSDU = maxSDU;
                    identification = ident;
                }

                @Override
                public String toString() {
                    return String.format("max-pdu=%d max-sdu=%d:ident=%s",
                            maxPDU, maxSDU, identification != null ? Utils.HEX.b2H(identification) : "n/a");
                }
            }

            /**
             * Represents special EACK packet parameters
             */
            public class EACKParams {
                public int[] seqNums;

                public EACKParams() {
                    try {
                        DataInputStream ds = new DataInputStream(new ByteArrayInputStream(getExtra_headers()));
                        int seqbytes = headerLen - staticHeaderLen; // The number of elements

                        seqNums = new int[seqbytes >= 0 ? seqbytes / 2 : 0]; // Two bytes per sequence number
                        for (int i = 0; i < seqNums.length; i++)
                            seqNums[i] = ds.readShort();
                    } catch (Exception ex) {
                    }
                }

                public EACKParams(int[] seqNums) {
                    this.seqNums = seqNums;
                }

                @Override
                public String toString() {
                    String out = "eack_seq<";
                    String sep = "";
                    for (int i = 0; i < seqNums.length; i++) {
                        out += String.format("%s%04d", sep, seqNums[i]);
                        sep = " ";
                    }
                    return out + ">";
                }
            }

            /**
             * Represents RST packet parameters
             */
            public class RSTParams {
                public static final int NORMAL = 0;
                public static final int CONNECT_FAILED_ILLEGAL_PARAM = 1;
                public static final int CONNECT_FAILED_TEMPORARY = 2;
                public static final int REQUESTED_PORT_NOT_AVAIL = 3;
                public static final int UNEXPECTED_PDU = 4;
                public static final int MAX_RETRIES_EXCEEDED = 5;
                public static final int VERSION_NOT_SUPPORTED = 6;
                public int reason;

                public RSTParams() {
                    reason = getExtra_headers()[0]; // First byte
                }

                public RSTParams(int reason) {
                    this.reason = reason;
                }

                @Override
                public String toString() {
                    return String.format("rst-code=%s", reason);
                }
            }
        }
    }

    /**
     * @brief The BIP context class. It needs to be special because it needs to hold the BIP connection object,
     * if any, the PUSH commands, etc
     */
    private class Context extends Transport.Context {

        public long tid;
        public boolean forcePush = false;
        public String TAR;
        public boolean doPush = false;
        public CatTP.Connection conn;
        private byte[] pushCmd = null; // The push command, as needed

        public Context(Eis sim, CatTP.Connection connection, int bufferLen, long tid, String pushTar) {
            super(sim, bufferLen, connection != null, false, false); // We allow chaining of commands provided we have a BIP connection, otherwise we do not.
            conn = connection;
            this.tid = tid;
            TAR = pushTar;
        }

        public byte[] makePushCmd() {
            if (pushCmd == null)

                try {
                    byte[] p2 = makePushCmd2(sim.activeMISDN(), tid);
                    pushCmd = new byte[pushCmd1.length + p2.length];
                    System.arraycopy(pushCmd1, 0, pushCmd, 0, pushCmd1.length);
                    System.arraycopy(p2, 0, pushCmd, pushCmd1.length, p2.length);

                } catch (Exception ex) {
                }
            return pushCmd;
        }

        public boolean usingPush() {
            return (conn == null && forcePush);
        }
    }

}

