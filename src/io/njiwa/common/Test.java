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

package io.njiwa.common;

import io.njiwa.common.model.RpaEntity;
import io.njiwa.common.rest.types.ReportsData;
import io.njiwa.common.rest.types.ReportsInputColumnsData;
import io.njiwa.common.rest.types.ReportsInputOrderData;
import io.njiwa.dp.model.ProfileTemplate;
import io.njiwa.dp.pedefinitions.EUICCResponse;
import io.njiwa.dp.pedefinitions.ProfileElement;
import io.njiwa.sr.model.Eis;
import io.njiwa.sr.transports.Transport;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import javax.annotation.PostConstruct;
import javax.ejb.Singleton;
import javax.ejb.Startup;
import javax.inject.Inject;
import javax.persistence.EntityManager;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Created by bagyenda on 15/01/2015.
 */
@Singleton
@Startup
public class Test {

    @Inject
    PersistenceUtility po;


    /**
     * @param em
     * @brief Generate fake events every so often
     */
    private void testEventsRecording(EntityManager em) {
        Random random = new SecureRandom();
        List<String> xsl;
        try {
            xsl = em.createQuery("from RpaEntity", RpaEntity.class).getResultList().stream().map(RpaEntity::getOid).collect(Collectors.toList());
        } catch (Exception ex) {
            xsl = new ArrayList<>();
        }
        final List<String> sl = xsl;
        Thread thread = new Thread(() -> {
            while (true) try {
                //   Utils.lg.info("Entered test stats generator...");
                final RpaEntity.Type[] ttypes = new RpaEntity.Type[]{RpaEntity.Type.SMDP, RpaEntity.Type.SMSR};
                try {
                    int n = ttypes.length + 1;
                    int i = random.nextInt(n);
                    RpaEntity.Type type = ttypes[i];
                    StatsCollector.recordTransaction(type);
                } catch (Exception ex) {
                    String xs = ex.getMessage();
                }
                // Generate a fake event

                try {
                    int n = ttypes.length;
                    int i = random.nextInt(n);
                    RpaEntity.Type type = ttypes[i];
                    n = 1 + StatsCollector.EventType.values().length; // In some cases it will not generate an event.
                    // Which is what we want
                    int j = random.nextInt(n);
                    StatsCollector.recordOwnEvent(type, StatsCollector.EventType.values()[j]);
                } catch (Exception ex) {
                    String xs = ex.getMessage();
                }

                // Fake transport events
                try {
                    int n = Transport.TransportType.values().length + 1;
                    int i = random.nextInt(n);
                    Transport.TransportType transportType = Transport.TransportType.values()[i];
                    n = Transport.PacketType.values().length + 1;
                    i = random.nextInt(n);
                    Transport.PacketType pktType = Transport.PacketType.values()[i];

                    StatsCollector.recordTransportEvent(transportType, pktType);

                } catch (Exception ex) {
                    String xs = ex.getMessage();
                }

                // Fake incoming events
                try {
                    // Do some crazy shit to get the list of Oids of other entities

                    int n = sl.size() + 1;
                    int j = random.nextInt(n);
                    String oid = sl.get(j);

                    n = 1 + StatsCollector.EventType.values().length;
                    j = random.nextInt(n);
                    StatsCollector.recordOtherEntityEvent(oid, StatsCollector.EventType.values()[j]);
                } catch (Exception ex) {
                    String xs = ex.getMessage();
                }

                Thread.sleep(500);

                //    Utils.lg.info("Leaving test stats generator.");
            } catch (Exception ex) {
            }
        });
        thread.start();
    }

    private void testReportsQuery(EntityManager em) {
        final Set<String> allowedOutputFields = new HashSet<>(Arrays.asList(new String[]{"meid", "eid", "platformType"
                , "dateAdded", "pendingProfileChangeTransaction", "remainingMemory", "productionDate",
                "cat_tp_support", "platformVersion", "smsr_id", "isd_p_module_aid", "availableMemoryForProfiles",
                "cat_tp_version", "secure_packet_version", "http_support", "remote_provisioning_version",
                "http_version", "oldSmsRId", "lastNetworkAttach", "lastAuditDate", "pendingEuiccHandoverTransaction",
                "isd_p_loadfile_aid", "imei", "Id", "registrationComplete", "eumId"}));
        ReportsInputColumnsData c =
                new ReportsInputColumnsData(new ReportsInputColumnsData.Column[]{new ReportsInputColumnsData.Column(
                        "Id", false, true), new ReportsInputColumnsData.Column("eid", true, true),
                        new ReportsInputColumnsData.Column("meid", true, true), new ReportsInputColumnsData.Column(
                                "platformType", new ReportsInputColumnsData.Column.Search("Samsung", false), true)});
        ReportsInputOrderData o =
                new ReportsInputOrderData(new ReportsInputOrderData.Order[]{new ReportsInputOrderData.Order(0, "asc")
                        , new ReportsInputOrderData.Order(1, "desc")});
        ReportsData r = ReportsData.doQuery(em, Eis.class, c, 0, o, 0, 13, allowedOutputFields);
        String res = r.toString();
    }


    private List testReadPT() throws Exception {
        FileInputStream f = new FileInputStream("/tmp/8991800099110000870.der");
        byte[] b = new byte[f.available()];

        f.read(b);
        f.close();

        List<ProfileElement> pl = ProfileTemplate.fromBytes(b);

        return pl;
    }

    private void readKeys(String file) throws Exception {

        Reader r = new FileReader(file);
        PemReader pf = new PemReader(r);
        PemObject o;

        KeyFactory kf = KeyFactory.getInstance("EC", ServerSettings.Constants.jcaProvider);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        while ((o = pf.readPemObject()) != null) {
            String xs = o.getClass().getCanonicalName();
            String t = xs;


            try {
                byte[] content = o.getContent();

                // Check if EC key
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(content);
                PrivateKey pkey = kf.generatePrivate(keySpec);
                String algo = kf.getAlgorithm();
                String xt = xs;
            } catch (Exception ex) {
                String s = ex.getLocalizedMessage();
            }
            try {
                // ByteArrayInputStream bi = new ByteArrayInputStream(content);
                // X509Certificate cert = (X509Certificate) cf.generateCertificate(bi);

                String xt = xs;
            } catch (Exception ex) {
            }
        }
    }

    @PostConstruct
    public void atStart() {
        // Test DB

        try {

            // readKeys("/tmp/sm-sr.pem");
            //      bootstrapKeysDB();

            // genbootstrapdata();

            //  outputKeyCerts();

            //   testReadPT();

        //    javax.crypto.Mac mac = javax.crypto.Mac.getInstance("DES", ServerSettings.Constants.jcaProvider);
         //       mac = javax.crypto.Mac.getInstance("AESCMAC", ServerSettings.Constants.jcaProvider);
        } catch (Exception ex) {
            String xs = ex.getMessage();
        }
        if (true) po.doTransaction(new PersistenceUtility.Runner<Object>() {

            @Override
            public void cleanup(boolean s) {
            }

            @Override
            public Object run(PersistenceUtility po, EntityManager em) throws Exception {
                //  SatGwSession sess = null;
                File file = null;
                FileInputStream f = null;
                BufferedReader bf;
                List<String> l;
                String s;

                try {
                    // outputKeyCerts();

                    testEventsRecording(em);
                    // addUsersAndGroups(em);
                    //  testReportsQuery(em);
                    EUICCResponse resp = new EUICCResponse();
                    resp.decode(new ByteArrayInputStream(new byte[]{0x30, 0x07, (byte) 0xA0, 0x05, 0x30, 0x3,
                            (byte) 0x80, 0x01, 0x0}), true);
                    String ciCertAlias = "ci";
                    //  X509Certificate ciCert = (X509Certificate) Utils.getKeyStore().getCertificate(ciCertAlias);
                    //  KeyPair kp = Utils.ECC.genKeyPair(5);
                    //   ECPrivateKey kpriv = (ECPrivateKey) kp.getPrivate();

                    //   ECPublicKey kpub = (ECPublicKey) kp.getPublic();
                    //  String xs = new ObjectMapper().writeValueAsString(kpub);

                    //    byte[] x1 = Utils.ECC.encode(kpriv);
                    //    byte[] x2 = Utils.ECC.encode(kpub);
                    //    String y2 = Utils.HEX.b2H(x2);

                    // Get them back
                    //   ECPrivateKey kpriv2 = Utils.ECC.decodePrivateKey(x1, 5);
                    //    ECPublicKey kpub2 = Utils.ECC.decodePublicKey(x2, 5);
                    //  Set<String> xset = getManagedClassAttributes(em, Eis.class);
                    //       String pubCertAlias = "inaere-sm-dp";
                    //         X509Certificate cert = (X509Certificate) Utils.getKeyStore().getCertificate
                    //         (pubCertAlias);
                    //  ECPublicKey kpub = (ECPublicKey) cert.getPublicKey();
                    //     byte[] ZAB = ECKeyAgreementEG.genZAB(kpriv, kpub);

                    String s1 = "-----BEGIN RSA PRIVATE KEY-----\n" +
                            "MIIEpAIBAAKCAQEAzdgPsopwdexcxbfXa3O5JYHQQONkq1h0lvGATul5DZZiQlkh\n" + "h+iJFdXA+KI8Z" +
                            "+jIIZo+3+phs5OeVDYipCARHAuV/HGoWR+4p6YB7cvEvCnSo0ss\n" +
                            "L3gbAfKoGS3g1JAtkEQLgpQKNkcZKeywEHIHbjbiijiTeVsagppyXsyNQPDGqU4E\n" + "9GqgoH7l" +
                            "/NNc1Z86fwnFzKxq2R1MPAC4mi7jNxGkBvc4+TFdESP/MyeCGd7lImrG\n" + "alX5" +
                            "+dnt9ZzCRV8WVkL0AlCxrKUMOoAKd5+2ymqf8e2Tbf9uwdl/4s1OK0Tv2j2J\n" + "5IQkaEg18cfW+NgS68V6R"
                            + "/xcLZcBdGw5bQmswwIDAQABAoIBAQDLRLozmAv4FyGB\n" + "ycp7fHpvtGI" +
                            "/QY3uulnfmLoYsutsZH3BgRzghduhaUS3AhZekfvXWucN3PkACR0H\n" +
                            "kbHhmxzqMfK5qE8TO4TwYLl05ozvNumfgSMv+Q3KfaJLwwdLQNkNpnQrTR9MfCc4\n" + "RFeU1dXKm35X+gh" + "/hVyHbhbU0HAImDZbyFGj1PKSB/tzzUA5MnN4jOUU67iIiBxL\n" + "0sxE3TC4cWQivNt3NcpsEay3YzMdeyytUIucuV9+lFTYqCpu6FiVtSlx5cQrZdIb\n" + "7YZgW68qxGhTNdp9nJ31EBy4euDyIlbd+Xh82TtYMCsHIWvQpNjnHDnrItF2c2Y2\n" + "iJTx8yepAoGBAOiNibjZmn/Xtd3AXmGgSSz4DmAhHesTwiEmSSqkYV+RiQwmcnz2\n" + "CSaa" + "/IkVdLIyQTn5E4bijIpyR8jho0UrzxCxivgyg6qCGzpsC5I3oV9Dd4chi9UB\n" + "SWLIU6OWjlm" + "/bNWfwIb0F3EzP4OILN0OCiJcR7jYBwEOiEtT++jZucodAoGBAOKZ\n" + "IrO0GO5LRvOYpDI77XdDQFie" + "/oGnH85YFclWGR/0+J6yNJNdC4cPJM/auqV3KZ25\n" + "3mb9wuBTeqqJ9O1q0TGmc8h4fX2kZ7UrFi9OwH8lPvJhz9Pn+EVFJLe7rNeMdirp\n" + "jLvGb6ZzzwOoOd1KJ1H2JAZXB97A6KWv6YXeRpxfAoGBAII1ldJ5jMdeKYeDSZVS\n" + "IQbb0XjDsjPIuV7ESB1nMtpG67xw3pPXUuJZz2KWL+QCvYDPVL6mpNh0CnuQ01FM\n" + "qUEIl" + "+5GonBbLxG0I3p4SZPEe+2eu+PFN6jmz+X9y7C2vSKTs0Ic8+8/KaXlHnGb\n" + "hdMdZk86LhnKYEgFOzxyhFOFAoGAf9tudD2Tr6m0EDE5vMqJtDizLw4PhzK4xKJ5\n" + "MJCvPpPoUQs2lUvz" + "/DI0UEAX/tNdHQ1Ki4x2EEOqPF35YJlcDorgW+Z40JManWQB\n" + "cZIbFeL7QKKmNOh38wYPsMhpv3oXFyGO8kkGqMJBtcuPUujLhPjA3P7whuUMoKjA\n" + "uHNyHjsCgYAaN4QwswoCeyEDgW07SULHEcEFT2KUQ388li/zAJU8zABatiDZbdvM\n" + "2q4kB2twhzCnJ9VpNp6k5zFSnhAKywCv4/xglqcFeVhjzC6gKF4DDd16XEJOsj5X\n" + "8ew7/tH2xVybv" + "+sxQ168j7vSYG48wEu8oifzOeI3oZuGy3VExpsxQQ==\n" + "-----END RSA PRIVATE KEY-----";
                    String s2 = "-----BEGIN EC PRIVATE KEY-----\n" +
                            "MHQCAQEEICAdZHbEufaNVPn0Sz2QQSUCkodpxgyM9iIgrk8P8br+oAcGBSuBBAAK\n" +
                            "oUQDQgAEc5PT6OwjPi1dOwzvt4OwGhLgqFVZH2+++rFlO9e4/Pt0MWvZIOj1AvRP\n" +
                            "oRTSgPSyNFQCIO2oFWvqe86XVYbo0g==\n" + "-----END EC PRIVATE KEY-----";
                    String s3 = "-----BEGIN PRIVATE KEY-----\n" +
                            "MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgIB1kdsS59o1U+fRLPZBB\n" +
                            "JQKSh2nGDIz2IiCuTw/xuv6hRANCAARzk9Po7CM+LV07DO+3g7AaEuCoVVkfb776\n" + "sWU717j8" +
                            "+3Qxa9kg6PUC9E+hFNKA9LI0VAIg7agVa+p7zpdVhujS\n" + "-----END PRIVATE KEY-----"; // PKCS#8
                    // format

                    //   Key k1 = Utils.keyFromFile(s1.getBytes("UTF-8"));
                    Key k2 = Utils.keyFromFile(s2.getBytes(StandardCharsets.UTF_8));
                    Key k3 = Utils.keyFromFile(s3.getBytes(StandardCharsets.UTF_8));
                    // String zabHex = Utils.HEX.b2H(ZAB);
                    // ECParameterSpec es = kpriv.getParams();

                    //   kpriv.get
                    Eis.Eid xeid = new Eis.Eid("8900 1567 01020304 0506 0708 0910 1152");
                    String cmd =
                            "00 20 15 16 21 15 15 00 00 00 25 C1 6F 34          \n" + "  0E 15 FC 71 C9 BE D1 " + "4A"
                                    + " 51 B1 6F 8C E7 44 69 C5    \n" + "  51 C8 DE 31";
                   /* String x = RpaEntity.canonicaliseSubject("C=CN, ST=Zhuhai, L=Zhuhai, O=XH Smartcard Ltd, " +
                            "CN=china-xinghan.com");
                    String y = RpaEntity.canonicaliseSubject("O=XH Smartcard Ltd, C=CN, ST=Zhuhai, L=Zhuhai,  " +
                            "CN=china-xinghan.com");
                    String z = RpaEntity.canonicaliseSubject("CN=china-xinghan.com, O=XH Smartcard Ltd, C=CN, " +
                            "ST=Zhuhai, L=Zhuhai  " +
                            "CN=china-xinghan.com");
                    byte[] t = z.getBytes();*/
                    // final byte[] udh = {0x02, 0x70, 0x00};
                    //     byte[] input = Utils.h2b(cmd.replaceAll("\\s+",""));

/*
                    // Canonicalise all the SubjectNames in RpEntries
                    List<RpaEntity> listA = em.createQuery("from RpaEntity ",RpaEntity.class).getResultList();

                    for (RpaEntity a: listA) {
                        String alias = a.getX509Subject();

                        String xAlias = RpaEntity.canonicaliseSubject(alias);
                        a.setX509Subject(xAlias);
                    }
                    em.flush();
*/

                    //  Utils.Pair<byte[], Ota.Params> res = Ota.unpackPkg(input, Transport.TransportType.SMS,
                    //  "+256782700042",udh,em);
                    //      byte[] xres = res.k;


                    String data = "9E 22 3C FC F7 B1 A8 99 FB BF EB 77\n" + "\n" + "                                 "
                            + "                                                       78 18 A3 68 8B A6 5D B7 33 A6 " + "5E " + "CD 68 0A 61 91                           \n" + "\n" + "                         " + "        " + "                                                       A8 7E B4 BF 98 B1 6D" + " 8A 81 9E 9E " + "F9 49 93 B6 4C                           \n" + "\n" + "               " + "                  " + "                                                       DF 6A A3 " + "A2 E0 88 45 C0 83 56 58 " + "62 85 EE 58 77                           \n" + "\n" + "    " + "                             " + "                                                      " + " 48 8D 62 5B BD 42 64 3A B1 49 B7 " + "5F 91 8B C8 AA                           \n" + "\n" + "                                 " + "                                           " + "            44 9C B7 6F 9E 3B 0E EB 0B 29 BD " + "13 9E DC 8A CC                        " + "   \n" + "\n" + "                                 " + "                                 " + "                      54 A0 3A 11 42 99 2C 2F DE B6 D2 " + "B0 DC A3 EE 60              " + "             \n" + "\n" + "                                 " + "                       " + "                                84 5E C6 24 18 22 2D 20 14 BC C5 " + "A8 10 FD A2 45    " + "                       \n" + "\n" + "                                 " + "             " + "                                          73 34 0E D4 FF 03 7C 19 58 4A 3B " + "B1 D1 B7" + " 09 2A                           \n" + "\n" + "                                 " + "   " + "                                                    0F 76 00 23 70 E5 10 1D AF A6 CE " + "2D 73 59 81 0F                           \n" + "\n" + "                                 " + "                                                       19 38 9B C1 EF 38 6D 34 D1 48 0C " + "F0 F3 B0 07 A0                           \n" + "\n" + "                                 " + "                                                       D2 66 43 8B 3A 11 B3 E1 37 DE 99 " + "00 7F 24 99 C4                           \n" + "\n" + "                                 " + "                                                       24 C6 C2 E9 B5 CB 1E 56 EC 27 23 " + "0F 50 F0 A6 75                           \n" + "\n" + "                                 " + "                                                       57 57 8D 65 A1 C9 64 45 DF 9A C0 " + "15 89 FC D2 8E                           \n" + "\n" + "                                 " + "                                                       4D 29 2C 00 55 2C C7 A2 9F 4A 07 " + "FD\n" + "\n" + "\n" + "35\n                                                             " + "                          FD D5 FD DB FA 22 59 21 6E AE 9C 32 99 C9 27 3F               " + "            \n" + "\n" + "                                                              " + "                          25 80 71 3D EA E3 75 2F AB 86 68 23 28 56 80 68               " + "            \n" + "\n" + "                                                              " + "                          DE D2 14 6A AE 6C 89 7F 12 4C F9 E4 42 C1 13 11               " + "            \n" + "\n" + "                                                              " + "                          A1 5F 24 50 07 98 75 B5 86 FB 50 EF 0F AC FA F0               " + "            \n" + "\n" + "                                                              " + "                          D0 A4 1C C3 45 84 D0 D8 9A 6A 1F E7 40 9D 42 A2               " + "            \n" + "\n" + "                                                              " + "                          43 74 72 55 04 E7 5E A2 94 CB 79 48 4A CE A2 37               " + "            \n" + "\n" + "                                                              " + "                          33 85 39 BB 4F 0B 23 7B 0E 5C 67 78 5C DB B7 19               " + "            \n" + "\n" + "                                                              " + "                          00 46 72 BA 02 33 D4 80 E7 25 66 5B 86 CB E4 FE               " + "            \n" + "\n" + "                                                              " + "                          F3 48 F6 65 C9 45 FF 47 04 70 4F 02 06 C5 D8 F9               " + "            \n" + "\n" + "                                                              " + "                          06 2C B1 A3 16 55 C3 6D 82 5D D7 A2 68 82 29 CD               " + "            \n" + "\n" + "                                                              " + "                          B6 10 72 3F F1 9D 56 35 5C 1A B5 58 88 3B 48\n";
                    // byte[] input = Utils.HEX.h2b(data.replaceAll("\\s+", ""));
                    //   byte[] key = Utils.HEX.h2b("AEF1E7DC23CA7FF3FCFDCDE45533D68C");
                    //   byte[] iv = Utils.HEX.h2b("181c280911feae3c");
                    //   byte[] out = Ota.Crypt.perform(input,key, Cipher.DECRYPT_MODE,iv);

// Make a session
                    // sess = new RedisSatGwSession(em);
/*
            FileInputStream fis = new FileInputStream("/tmp/rfmkey.txt");
            BufferedReader b = new BufferedReader(new InputStreamReader(fis));
           List<String> l = new ArrayList<String>();

            String line;
            while ((line = b.readLine()) != null)
                l.add(line);
            SimRfmKey.saveFromFile(hEntityManager,l.toArray(new String[0]));

*/

//                    sess.trusted = true;





/*
                file  = new File("/tmp/x.cap");
                f = new FileInputStream(file);
                byte[] in = new byte[(int)file.length()];
                f.read(in);
                JavaCardPackage.fromCapFile(em, in, "SendUSSD", "1.0");
*/


/*
            file = new File("/tmp/sample-prof.xml");
            f = new FileInputStream(file);
            byte[] data = new byte[(int) file.length()];
            f.read(data);

            CardProfile p = CardProfile.parseProfile(em, new String(data, "UTF-8"));
            // em.persist(p);

*/
/*

                    file = new File("/tmp/c.xml");
                    f = new FileInputStream(file);
                    byte[] xdata = new byte[(int)file.length()];
                    f.read(xdata);
                    SatApplicationCollection c = SatApplicationCollection.parseLegacy(xdata);
                    em.persist(c);
                    em.flush();
*/
/*


                    file = new File("/tmp/sim-data.txt");
                    bf = new BufferedReader(new FileReader(file));
                    List<String> l = new ArrayList<String>();
                    String s;
                    while((s = bf.readLine())!= null)
                        l.add(s);

                    CardProfile.saveSimsFromFile(po, em, "Viettel Profile X", null, l.toArray(new String[0]));
                   // em.flush();

*/
/*
                    file = new File("/tmp/rfmkeys-data.txt");
                    bf = new BufferedReader(new FileReader(file));
                     l = new ArrayList<String>();

                    while((s = bf.readLine())!= null)
                        l.add(s);
                    SimRfmKey.saveFromFile(po,em,l.toArray(new String[0]));
*/
                    //   em.flush();
          /*  BufferedReader in = new BufferedReader(new FileReader("/tmp/cp.txt"));

            List<String> l = new ArrayList<String>();
           String s;
            while ((s = in.readLine()) != null)
                l.add(s);
            CardProvisioningRange.loadFromFile(hEntityManager,l.toArray(new String[0]));
*/
                    //      Simcard sim = Simcard.getSimbyMSISDN(hEntityManager, "12221");

/*
                    file = new File("/tmp/c.xml");
                    f = new FileInputStream(file);
                    byte[] xdata = new byte[(int)file.length()];
                    f.read(xdata);
                    SatApplicationCollection c = SatApplicationCollection.parseLegacy(xdata);
                    em.persist(c);
                    em.flush();
*/

                    //  em.flush();

                } catch (Exception ex) {
                    ex.printStackTrace();
                } finally {
                    //sess.close();

                }
                return null;
            }
        });


    }


}
