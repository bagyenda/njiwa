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
import io.njiwa.common.ServerSettings;
import io.njiwa.sr.model.DlrTracker;
import io.njiwa.sr.model.Eis;
import io.njiwa.sr.ota.Ota;

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
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;


/**
 * @addtogroup g_transports
 * @{
 */

/**
 * @brief This is the SMS Transport implementation
 */
@Singleton(name = "Sms")
@Startup
@ConcurrencyManagement(ConcurrencyManagementType.BEAN)
public class Sms extends Transport {
    public static final int MAX_SMS_OCTETS = 140; //!< Maximum size of a single SMS
    public static final int DC_UNDEF = -1;
    public static final int DC_7BIT = 0;
    public static final int DC_8BIT = 1;
    public static final int DC_UCS2 = 2;
    public static final int MC_UNDEF = -1;
    public static final int MAX_CSMS = 20;
    public static final int MAX_SMS_LEN = MAX_SMS_OCTETS * MAX_CSMS;
    public static final int MAX_APDUS_FOR_SMS = 5;

    private static ServerSocket vsmsc_sock; //!< The virtual SMSC socket
    private static Map<String, VirtualDevice> devList = new ConcurrentHashMap<String, VirtualDevice>(); //!< List of connections to the virtual SMSC, indexed by msisdn
    private static Thread smscTh; //!< Virtual SMSC handler thread
    private static SmscReceiver receiver; //!< Virtual SMSC receiver
    private static ManagedExecutorService vsmscDlrExecutor;
    // Our peristence container, for our uses.
    // private static PersistenceUtil po = null;
    private static Instance<PersistenceUtility> poTasks = null;

    static {
        Sms s = new Sms();
        TransportType.transportMap.put(TransportType.SMS, s);
    }

    @Inject
    Instance<PersistenceUtility> xpoTasks;
    @Resource
    private ManagedExecutorService xvsmscDlrExecutor;

    public Sms() {
        unit = "sms";
    }

    /**
     * @param msisdn
     * @param socket
     * @return
     * @brief make a virtual SMSC receive object
     */
    public static VirtualDevice makeDev(String msisdn, Socket socket) {
        if (msisdn != null && msisdn.length() > 0) {
            VirtualDevice d = devList.get(msisdn);

            if (d != null)
                return d;
            d = new VirtualDevice(msisdn, socket);
            devList.put(msisdn, d);
            return d;
        } else
            // We need to allocate a phone number
            for (int i = 0; i < 100000; i++) {
                msisdn = String.format("%s%06d", ServerSettings.getVsmscnumberPrefix(), i);
                VirtualDevice d = new VirtualDevice(msisdn, null);
                if (devList.put(msisdn, d) == null) {
                    // We got one
                    d.socket = socket;
                    return d;
                }
            }
        return null;
    }

    private static synchronized void startVsmsc() throws Exception {
        if (vsmsc_sock == null) {
            vsmsc_sock = new ServerSocket(ServerSettings.getVsmscPort());

            receiver = new SmscReceiver();
            smscTh = new Thread(receiver);
            smscTh.start();
        }
    }

    private static synchronized void stopVsmsc() throws Exception {
        try {
            vsmsc_sock.close();
        } catch (Exception ex) {
        }
        try {
            receiver.setStop();
            smscTh.interrupt();
            smscTh.wait();
            vsmsc_sock = null;
        } catch (Exception ex) {
        }
    }

    /**
     * @param dev
     * @param text
     * @param pid
     * @param dcs
     * @param udh
     * @param request_por
     * @param smsID
     * @param tag
     * @param partNo
     * @param tagID
     * @return
     * @throws Exception
     * @brief send a single SMS to a virtual device (STK emulator) connected to the virtual SMSC
     */
    private static boolean sendSms(VirtualDevice dev, byte[] text, int pid, int dcs, byte[] udh,
                                   int request_por,
                                   long smsID,
                                   String tag,
                                   int partNo,
                                   long tagID) throws Exception {
        // Send to device
        dev.lastUse = Calendar.getInstance().getTime();

        // Make the time
        Utils.Pair<byte[], Integer> smsc = Utils.makePhoneNumber(ServerSettings.getVsmsc_number().getBytes(StandardCharsets.UTF_8));

        // Make an SMS-DELIVER PDU - Sec 9.2.2.1 of GSM 03.40
        /* TP-UDHI: Page 36 of GSM 03.40 gives order */
        int h1 = (udh != null && udh.length > 0) ? (1 << 6) : 0;
        ByteArrayOutputStream tpdu = new ByteArrayOutputStream();
        tpdu.write(h1);
        // Write the SMSC address. First its length in bytes, then itself
        tpdu.write(smsc.l);
        tpdu.write(smsc.k);

        tpdu.write(new byte[]{
                (byte) pid,
                (byte) dcs
        });
        // Write blank tp-scts
        tpdu.write(new byte[7]);
        int udhlen = (udh != null) ? udh.length : 0;
        int udl = text.length + udhlen;
        tpdu.write(udl);
        if (udhlen > 0)
            tpdu.write(udh);
        tpdu.write(text);

        byte[] msgBytes = tpdu.toByteArray();
        Utils.lg.info(String.format("Vsms: Queueing %d bytes (%d sms bytes) to [%s] for tracker [%s]: %s",
                tpdu.size(), text.length, dev.msisdn, smsID, Utils.HEX.b2H(msgBytes)));

        DataOutputStream out = new DataOutputStream(dev.socket.getOutputStream());

        out.write((Utils.urlEncode(msgBytes) + "\n").getBytes(StandardCharsets.UTF_8));
        out.flush();

        if (request_por != 0 &&
                (request_por & (DLR_DELIVERED_TO_SMSC | DLR_DELIVERED_TO_PHONE)) != 0) // indicated delivered to SMSC
            queueDlr(dev.msisdn, DLR_DELIVERED_TO_PHONE, smsID, tag, tagID, partNo);


        return true;
    }

    /**
     * @param msisdn
     * @param dlrCode
     * @param smsId
     * @param tag
     * @param tagID
     * @param partNo
     * @brief Route a DLR message received from the virtual SMSC back into the Gateway.
     * Note that we must do this asynchronously in order not to lock ourselves up in recursive calls due to
     * the DLR triggering another transaction send.
     */
    private static void queueDlr(final String msisdn, final int dlrCode,
                                 final long smsId, final String tag, final long tagID, final int partNo) {

        // Do not run it in current thread. Right?
        vsmscDlrExecutor.submit(
                () -> {
                        PersistenceUtility po = poTasks.get(); // Get a persistence util
                        try {
                            Thread.sleep(10); // Wait a little before reporting the DLR...
                        } catch (Exception ex) {
                        }
                        receiveDlr(po, msisdn,
                                dlrCode,
                                smsId, tag,
                                tagID,
                                partNo);

                    }
                );
    }

    /**
     * @param text
     * @param udh
     * @param msidn
     * @param dlr_url
     * @param request_por
     * @param coding
     * @return
     * @throws Exception
     * @brief Send SMS to an external MSISDN (i.e. one not connected via the virtual SMSC)
     */
    private static boolean sendSms(byte[] text, byte[] udh, String msidn,
                                   String dlr_url, int request_por, int coding) throws Exception {
        boolean res;

        String url = String.format("%s%stext=%s&to=%s",
                ServerSettings.getSendSmsUrl(),
                ServerSettings.getSendSmsUrl().contains("&") ? "&" : "?",
                Utils.urlEncode(text),
                URLEncoder.encode(msidn, StandardCharsets.UTF_8.toString())
        );
        if (udh != null && udh.length > 0)
            url += String.format("&udh=%s", Utils.urlEncode(udh));

        if (request_por != 0 && dlr_url != null && dlr_url.length() > 0) {
            url += String.format("&dlr-url=%s&dlr-mask=%d",
                    URLEncoder.encode(dlr_url, StandardCharsets.UTF_8.toString()), request_por);
        }

        if (coding != 0)
            url += String.format("&coding=%s", coding);
        try {
            Utils.Triple<Integer, Map<String, String>, String> out = Utils.getUrlContent(url,
                    Utils.HttpRequestMethod.GET, null,
                    null, null);
            int code = out.k;

            res = (code / 100 == 2); // Success code.

            if (!res)
                Utils.lg.severe(String.format("Failed to send sms to [%s]: http code [%d: %s]",
                        msidn, code, out.m));
        } catch (Exception ex) {
            res = false;
            Utils.lg.severe(String.format("Failed to send sms to [%s]: %s", msidn, ex));
        }

        return res;
    }

    /**
     * @param l - the list of APDUs
     * @return
     * @brief estimate if we can use SMS
     */
    public boolean canUseSMS(List<byte[]> l) {
        try {
            if (l.size() > MAX_APDUS_FOR_SMS)
                return false;
            int largest = Collections.max(l, new Comparator<byte[]>() {
                @Override
                public int compare(byte[] o1, byte[] o2) {
                    return o1.length - o2.length;
                }
            }).length;

            if (largest >= MAX_SMS_LEN)
                return false;
            return true;
        } catch (Exception ex) {

        }
        return false;
    }

    @Override
    @PostConstruct
    public synchronized void start() {

        // po = xpo;
        poTasks = xpoTasks;
        vsmscDlrExecutor = xvsmscDlrExecutor; // Grab it.
        try {
            startVsmsc();
        } catch (Exception ex) {
            Utils.lg.severe(String.format("Error starting SMS transport: %s", ex));
        }
    }

    @Override
    @PreDestroy
    public void stop() {
        try {
            stopVsmsc();
        } catch (Exception ex) {
            Utils.lg.severe(String.format("Error stopping SMS transport: %s", ex));
        }
    }

    private String mkDlrUrl(Context context, int mask, long trackerId) throws Exception {
        // Return a kannel-style DLR url
        return String.format("http%s://%s:%d%s?from=%s&dlr=%%d&reqids=%s&data=%%b&dlr_tag=%s&dlr_id=%d&oflag=%d&sms_id=%d",
                ServerSettings.isUseSSL() ? "s" : "",
                ServerSettings.getMyhostname(),
                ServerSettings.getMyport(),
                ServerSettings.getDlrUri(),
                context.sim.activeMISDN(),
                URLEncoder.encode(context.requestID, StandardCharsets.UTF_8.toString()),
                context.tag,
                context.tagId,
                mask, trackerId);
    }

    private void logSms(String to, byte[] text, byte[] udh) {
        Utils.lg.info(String.format("Sent SMS [to: %s], [Udh: %s], [Text: %s]",
                to,
                udh != null ? Utils.HEX.b2H(udh) : "",
                Utils.HEX.b2H(text)));
    }

    /**
     * Send a CSMS to a SIM
     *
     * @param em
     * @param context
     * @param msg
     * @param dlr_flags
     * @return
     * @throws Exception
     */
    @Override
    public Utils.Triple<Integer, MessageStatus, Long> sendMsg(EntityManager em, Context context, byte[] msg, int dlr_flags) throws Exception {
        String dlr_url = "";
// Make tracker
        DlrTracker tracker;
        String msisdn = context.sim.activeMISDN();
        VirtualDevice vdev = devList.get(msisdn); // Check if we have a virtually connected one.
        long trackerId = 0;
        if (dlr_flags != 0) {
            tracker = new DlrTracker(msisdn);
            em.persist(tracker); // So we get an ID
            trackerId = tracker.getId();
        } else
            tracker = null;

        try {
            dlr_url = mkDlrUrl(context,
                    dlr_flags >> 8, trackerId);
        } catch (Exception ex) {
            dlr_url = "";
        }
        if (context.tag != null)
            dlr_flags = 1;

        if (context.ucs2Sms)
            try {
                // Convert to UTF-18
                byte[] xmsg = (new String(msg, StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_16BE);
                msg = xmsg;
            } catch (Exception ex) {

            }

        int n = Ota.smsCount(msg.length);

        MessageStatus status;
        int count = 0;
        boolean res = false;
        List<DlrTracker.MessagePart> l = (tracker != null) ? tracker.getMessageParts() : new ArrayList<DlrTracker.MessagePart>();

        if (n <= 1) {
            // Only one message
            byte[] udh = context.no0348coding ? null : Utils.HEX.h2b("027000");
            String xdlr_url = String.format("%s&part_no=0", dlr_url);

            if (tracker != null) {
                DlrTracker.MessagePart m = new DlrTracker.MessagePart();
                m.setPartNo(0);
                l.add(m);
                em.flush(); // Really?
            }
            // Send the message
            if (vdev == null)
                res = sendSms(msg, udh, msisdn, xdlr_url, dlr_flags, context.ucs2Sms ? 2 : 0);
            else
                res = sendSms(vdev, msg, context.no0348coding ? 0x00 : 0x7f,
                        context.no0348coding ? context.ucs2Sms ? 0x08 : 0x00 : 0xF6,
                        udh, dlr_flags, trackerId,
                        context.tag, 0,
                        context.tagId);

            if (res) {
                StatsCollector.recordTransportEvent(TransportType.SMS,PacketType.MT); // count stats
                logSms(msisdn, msg, udh);
                count = 1;
            }
        } else {
            long ref = System.currentTimeMillis() % 1023; // Make a message reference.
            int offset = 0;
            for (int i = 0; offset < msg.length; i++) {
                ByteArrayOutputStream udh = new ByteArrayOutputStream();
                String xdlr_url = String.format("%s&part_no=%d", dlr_url, i);
                if (context.no0348coding) { // Concat only...
                    udh.write(new byte[]{
                            0x00,
                            0x03,
                            (byte) ((ref + trackerId) & 0xFF), // Ref
                            (byte) n, // Num messages
                            (byte) (i + 1), // Sequence number, starting at 1
                    });
                } else {
                    if (i == 0)
                        udh.write(new byte[]{0x07, 0x70, 0x00}); // First one gets the security identifier.
                    else
                        udh.write(0x05);

                    udh.write(new byte[]{
                            0x00, // Concat marker
                            0x03, // Length of contact
                            (byte) ((ref + trackerId) & 0xFF), // Ref
                            (byte) n, // Num messages
                            (byte) (i + 1), // Sequence number, starting at 1
                    });
                }
                int tSize = MAX_SMS_OCTETS - udh.size();
                byte[] text = Utils.byteArrayCopy(msg, offset, tSize);
                offset += tSize; // Skip forward the amount read, or go past end of string.

                if (ServerSettings.getSmsThroughput() > 0 && i > 0)
                    try {
                        long millisecs = 1000 / ServerSettings.getSmsThroughput();
                        Thread.sleep(millisecs);
                    } catch (Exception ex) {
                    }

                if (tracker != null) {
                    DlrTracker.MessagePart m = new DlrTracker.MessagePart();
                    m.setPartNo(i);
                    l.add(m);
                    em.flush(); // Really?
                }
                byte[] xudh = udh.toByteArray();

                // Send the message
                if (vdev == null)
                    res = sendSms(text, xudh, msisdn, xdlr_url, dlr_flags, context.ucs2Sms ? 2 : 0);
                else
                    res = sendSms(vdev, text, context.no0348coding ? 0x00 : 0x7f,
                            context.no0348coding ? context.ucs2Sms ? 0x08 : 0x00 : 0xF6,
                            xudh, dlr_flags, trackerId, context.tag, i,
                            context.tagId);

                if (res) {
                    logSms(msisdn, text, xudh);

                    count++;
                }
            }
        }
        if (em != null && tracker != null) {
            tracker.setMessageParts(l);
            em.persist(tracker);
        }

        status = count > 0 ? MessageStatus.Sent : MessageStatus.NotSent;
        return new Utils.Triple<Integer, MessageStatus, Long>(count, status, -1L);
    }

    @Override
    public boolean isRunning() {
        return started;
    }

    @Override
    public TransportType sendMethod() {
        return TransportType.SMS;
    }

    @Override
    public Context getContext(Eis sim, Ota.Params params, long transID, int pktSize) {
        Context c = new Context(sim, MAX_CSMS, true, false, false);
        return c;
    }

    @Override
    public boolean hasEnoughBuffer(Context ctx, int dlen) {
        int n = Ota.smsCount(dlen);
        return n < ctx.maxMessageSize; // Message size is measured in SMS...
    }

    @Override
    public int unitsCount(int dlen) {
        return Ota.smsCount(dlen);
    }

    @Override
    public String getName() {
        return "sms";
    }

    /**
     * @brief This is a virtual device/SIM connected to our virtual SMSC
     */
    private static class VirtualDevice {
        public String msisdn; //!< The Registered MSISDN
        public Socket socket; //!< The actual network socket on which it listens for MT SMS

        Date lastUse = Calendar.getInstance().getTime(); //!< When it was last used

        public VirtualDevice(String msisdn, Socket socket) {
            this.msisdn = msisdn;
            this.socket = socket;

        }

        @Override
        protected void finalize() {
            try {
                socket.close();
            } catch (Exception ex) {
            }
        }
    }

    /**
     * @brief this is the virtual SMSC processor. It implements a very simple protocol for receiving and sending messages
     * Each command is of the form:
     * cmd arg1 arg2 ...
     * <p>
     * Arguments are URL-encoded. Only one command is sent per line.
     * Commands are:
     * - send - To send a CSMS into the gateway
     * - register - to register to the virtual SMSC
     * - deregister - to deregister from the virtual SMSC
     * In turn the Virtual SMSC can send MT SMS using by simply sending the url-encoded SMS TPDU on the connected
     * file descriptor of the virtual device
     */
    private static class SmscReceiver implements Runnable {
        private static final int MAX_AGE = 60 * 30; // 30 minutes idle, we kill you
        private static final int CLEANUP_INTERVAL = 10;
        private boolean stop = false;
        private int cleanup_ct = 0;

        private synchronized void doCleanup() {
            cleanup_ct++;

            if (cleanup_ct % CLEANUP_INTERVAL != 0)
                return;

            long currentT = Calendar.getInstance().getTimeInMillis();
            List<String> stale = new ArrayList<String>();
            for (Map.Entry<String, VirtualDevice> d : devList.entrySet())
                if (currentT - d.getValue().lastUse.getTime() > MAX_AGE * 1000)
                    stale.add(d.getKey());
            for (String msisdn : stale) {
                devList.remove(msisdn);
                Utils.lg.info(String.format("Vsms: De-registered stale device [%s]", msisdn));
            }
        }

        public void setStop() {
            stop = true;
        }

        public void run() {
            Socket socket, xsocket;
            DataOutputStream out = null;
            Utils.lg.info(String.format("Starting virtual SMSC on port [%d]...", ServerSettings.getVsmscPort()));
            // Run the receiver queue
            while (!stop)
                try {
                    socket = xsocket = vsmsc_sock.accept();
                    Utils.lg.info(String.format("Received Virtual SMSC connect from [%s:%d]", socket.getInetAddress(), socket.getPort()));

                    BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                    out = new DataOutputStream(socket.getOutputStream());
                    String reply = "Ok";
                    boolean replySent = false;
                    VirtualDevice dev;
                    int i = 0;

                    // Read line
                    String req = in.readLine();
                    Utils.lg.info(String.format("VSMSC [%s:%d]<---%s", socket.getInetAddress(), socket.getPort(), req));
                    String[] xl = req.split("\\s+");

                    String command = xl[i++];

                    String from;
                    try {
                        int j = i;
                        String x = Utils.cleanPhoneNumber(xl[j]); // The number
                        i++;
                        from = x;
                    } catch (Exception ex) {
                        from = i < xl.length ? xl[i] : null; // Should we keep the 'unclean' number? Perhaps.
                        i++; // Skip past it. Right?
                    }
                    // Now look at the commands.
                    if (req.contains("license") && command.contains("GET")) {
                        // Fake HTTP, license check
                        // Get all
                        char[] xin = new char[1];
                        int l = 0;
                        socket.setSoTimeout(100);

                        try {
                            while (in.read(xin) > 0)
                                l++;
                        } catch (Exception ex) {
                        }
                        String r = String.format("SMSC: %d\r\n", ServerSettings.getVsmscPort());
                        SimpleDateFormat df = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss z");
                        Date dt = Calendar.getInstance().getTime();

                        out.write("HTTP/1.1 200 OK\r\n".getBytes(StandardCharsets.UTF_8));
                        out.write("Connection: close\r\n".getBytes(StandardCharsets.UTF_8));
                        out.write("Content-Type: text/plain\r\n".getBytes(StandardCharsets.UTF_8));
                        out.write(String.format("Content-Length: %d\r\n", r.length()).getBytes(StandardCharsets.UTF_8));

                        out.write(String.format("Date: %s\r\n", df.format(dt)).getBytes(StandardCharsets.UTF_8));
                        out.write("Server: anon/1.1\r\n".getBytes(StandardCharsets.UTF_8));
                        out.write(("\r\n\r\n" + r).getBytes(StandardCharsets.UTF_8));
                        reply = "";
                    } else if (command.equalsIgnoreCase("register")) {
                        // Device wishes to register...
                        dev = makeDev(from, socket);
                        if (dev == null)
                            Utils.lg.severe(String.format("Vsmsc: Failed to create virtual device for [%s]",
                                    from != null ? from : "n/a"));
                        else {
                            reply = dev.msisdn;
                            socket = null; // Captured.
                            Utils.lg.info(String.format("Vsmsc: Device [%s] registered",
                                    reply));
                        }
                    } else if (command.equalsIgnoreCase("deregister")) {
                        if (from != null)
                            dev = devList.remove(from);
                        else
                            dev = null;
                        if (dev == null)
                            Utils.lg.severe(String.format("Vsmsc: Failed to de-register device for [%s]",
                                    from != null ? from : "n/a"));
                        else
                            Utils.lg.info(String.format("Vsmsc: Device [%s] de-registered",
                                    from));
                        // dev.socket.close();
                        //  dev = null; // Clear it.
                    } else if (command.equalsIgnoreCase("dlr")) {
                        PersistenceUtility po = poTasks.get();
                        receiveDlr(po, from, 1, 0, "trans", 0L, 0); // XXX Change these flags.
                    } else if (command.equalsIgnoreCase("send")) {
                        dev = devList.get(from);
                        String tpdu = xl[i++];
                        if (dev == null || tpdu == null || tpdu.length() == 0) {
                            Utils.lg.severe(String.format("Vsms: Received 'send' from unregistered device [%s]", from != null ? from : "n/a"));
                            continue;
                        }

                        byte[] xtpdu = Utils.urlDecode(tpdu);
                        Utils.lg.info(String.format("Vsms: Received 'send' from device [%s], %d bytes",
                                from,
                                xtpdu.length));

                        int ch = xtpdu[0];

                        if ((ch & 0x03) != 0x01) {
                            Utils.lg.severe(String.format("Vsms: Received non-SUBMIT-SM  from device [%s]",
                                    from));
                            continue;
                        }

                        dev.lastUse = Calendar.getInstance().getTime(); // Indicate latest usage.

                        // This is the SMS TDPU parsing a la GSM 03.40. This is an SMS-SUBMIT packet (see sec 9.2.2.2)
                        int udhi = (ch >> 6) & 0x01;
                        int x = (ch >> 3) & 0x03;
                        int vp_len = (x == 0) ? 0 : (x == 2) ? 1 : 7;

                        ch = xtpdu[2];
                        Utils.Pair<String, Integer> pres = Utils.parsePhoneFromSemiOctets(xtpdu, ch, 3);
                        int da_len = pres.l;
                        String to = pres.k;
                        int tp_pid = xtpdu[3 + da_len];
                        int tp_dcs = xtpdu[4 + da_len];
                        int coding = DC_UNDEF;
                        int mclass = MC_UNDEF;
                        boolean alt_dcs = false;
                        boolean compress = false;

                        // Break down DCS flags
                        if ((tp_dcs & 0xF0) == 0xF0) {
                            tp_dcs &= 0x07;
                            coding = (tp_dcs & 0x04) != 0 ? DC_8BIT : DC_7BIT; /* grab bit 2 */
                            mclass = tp_dcs & 0x03; /* grab bits 1,0 */
                            alt_dcs = true; /* set 0xFX data coding */
                        }

                    /* Non-MWI Mode 0 */
                        else if ((tp_dcs & 0xC0) == 0x00) {
                            alt_dcs = false;
                            compress = ((tp_dcs & 0x20) == 0x20) ? true : false; /* grab bit 5 */
                            mclass = ((tp_dcs & 0x10) == 0x10) ? tp_dcs & 0x03 : MC_UNDEF;
                                                /* grab bit 0,1 if bit 4 is on */
                            coding = (tp_dcs & 0x0C) >> 2; /* grab bit 3,2 */
                        }

                      /* MWI */
                        else if ((tp_dcs & 0xC0) == 0xC0) {
                            alt_dcs = false;
                            coding = ((tp_dcs & 0x30) == 0x30) ? DC_UCS2 : DC_7BIT;
                        }

                        int udl = xtpdu[5 + da_len + vp_len];

                        // Get the SMS
                        byte[] sms = Arrays.copyOfRange(xtpdu, 6 + da_len + vp_len, xtpdu.length);


                        byte[] udh;
                        if (udhi != 0) {
                            // We have UDH. SO
                            int udh_len = sms[0];
                            udh = Arrays.copyOfRange(sms, 0, udh_len + 1);
                            sms = Arrays.copyOfRange(sms, udh_len + 1, sms.length);
                        } else
                            udh = new byte[0];
                        int udhlen = udh.length;
                        // Massage message
                        if (coding != DC_8BIT && coding != DC_UCS2) {
                            // 7bit encoding
                            int offset = 0;
                            if (udhi != 0 && coding == DC_7BIT) {
                                int nbits = (udhlen + 1) * 8;
                                offset = (((nbits / 7) + 1) * 7 - nbits) % 7;
                                udl -= ((udhlen + 1) * 8 + offset) / 7; /* remove UDH len septets. */
                            }

                            try {
                                byte[] t = Charset.decode7Bituncompressed(sms, udl, offset, true);
                                sms = t;
                            } catch (Exception ex) {
                            }
                        } else if (udhi != 0)
                            udl -= udhlen + 1;

                        Utils.lg.info(String.format("vsmsc: Received [to: %s], [udh: %s], [text: %s]", to,
                                udh != null ? Utils.HEX.b2H(udh) : "n/a",
                                Utils.HEX.b2H(sms)));

                        // Find destination: Ignore short codes for now, all go to GW
                        boolean forgw = true; // to.equalsIgnoreCase(Properties.getVsmsc_number());

                        //  if (!forgw)
                        //      for (i = 0; i < Properties.getVsmscGwShortCodes().length; i++)
                        //          if (Properties.getVsmscGwShortCodes()[i].equalsIgnoreCase(to)) {
                        //              forgw = true;
                        //              break;
                        //         }
                        reply = Utils.urlEncode(sms);
                        out.write((reply + "\n").getBytes(StandardCharsets.UTF_8));
                        replySent = true;
                        final byte[] xsms = sms, xudh = udh;
                        final String xfrom = from;
                        if (forgw) {
                            PersistenceUtility po = poTasks.get();
                            po.doTransaction(new PersistenceUtility.Runner<Object>() {
                                @Override
                                public Object run(PersistenceUtility po, EntityManager em) throws Exception {
                                    Ota.receiveMO(xsms, TransportType.SMS, xfrom, xudh, em);
                                    return null;
                                }

                                @Override
                                public void cleanup(boolean success) {

                                }
                            });

                            // Else, send via external. Right?
                        } else
                            sendSms(sms, udh, to, null, 0, 0);


                    }

                    if (reply != null) {
                        if (!replySent)
                            out.write((reply + "\n").getBytes(StandardCharsets.UTF_8));
                        Utils.lg.info(String.format("VSMSC [%s:%d]--->%s", xsocket.getInetAddress(), xsocket.getPort(), reply));
                    }
                    if (socket != null)
                        socket.close(); // Only works if above didn't capture it
                } catch (Exception ex) {
                    Utils.lg.severe(String.format("Error in vsmsc: %s", ex));
                    if (out != null)
                        try {
                            out.write("Error".getBytes(StandardCharsets.UTF_8));
                        } catch (Exception ex2) {
                        }
                } finally {
                    try {
                        doCleanup(); // Clean up.
                    } catch (Exception ex) {
                    }
                }

            Utils.lg.info(String.format("Stopped virtual SMSC on port [%d]", ServerSettings.getVsmscPort()));
        }
    }


}

/**
 * @}
 */