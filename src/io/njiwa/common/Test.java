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
import io.njiwa.sr.ota.Ota;
import io.njiwa.sr.transports.Transport;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import javax.annotation.PostConstruct;
import javax.ejb.Singleton;
import javax.ejb.Startup;
import javax.inject.Inject;
import javax.persistence.EntityManager;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
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


    private void testParseOTaResp(String resp) throws Exception {
        byte[] data = Utils.HEX.h2b(resp);

        Ota.ResponseHandler.RemoteAPDUStructure rp = Ota.ResponseHandler.RemoteAPDUStructure.parse(data);
        if (rp instanceof Ota.ResponseHandler.ETSI102226APDUResponses) {
            boolean success = ((Ota.ResponseHandler.ETSI102226APDUResponses) rp).isSuccess; // Whether success
            String xstatus = ((Ota.ResponseHandler.ETSI102226APDUResponses) rp).formattedResponse;


        }
    }

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
        final Set<String> allowedOutputFields = new HashSet<>(Arrays.asList("meid", "eid", "platformType", "dateAdded"
                , "pendingProfileChangeTransaction", "remainingMemory", "productionDate", "cat_tp_support",
                "platformVersion", "smsr_id", "isd_p_module_aid", "availableMemoryForProfiles", "cat_tp_version",
                "secure_packet_version", "http_support", "remote_provisioning_version", "http_version", "oldSmsRId",
                "lastNetworkAttach", "lastAuditDate", "pendingEuiccHandoverTransaction", "isd_p_loadfile_aid", "imei", "Id", "registrationComplete", "eumId"));
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

        final List<ProfileElement> pl = ProfileTemplate.fromBytes(b);

        po.doTransaction((po, em) -> {
            RpaEntity mno = RpaEntity.getByUserId(em, "mno1");
            ProfileTemplate profileTemplate = new ProfileTemplate(mno, pl, ProfileTemplate.DataSourceType.Database);

            em.persist(profileTemplate);
            return false;
        });

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

    private void testPP() { // Test parse an SMS-DELIVER
        byte[] x = {0x40, 0x05, (byte) 0x81, 0x12, 0x50, (byte) 0xF3, (byte) 0x96, (byte) 0xF6, 0x22, 0x22, 0x22,
                0x22, 0x22, 0x22, 0x22};
        int pos = 1;
        int num_len = x[pos++];
        Utils.Pair<String, Integer> pres = Utils.parsePhoneFromSemiOctets(x, num_len, pos);
        int da_len = pres.l;
        String to = pres.k;
        pos += da_len;
        int tp_pid = x[pos];
        pos++;
        int tp_dcs = x[pos];
        pos++;
        int scts_pos = pos;
        byte[] scts = Arrays.copyOfRange(x, scts_pos, scts_pos + 7);
        Utils.lg.warning("Test" + tp_dcs);
    }


    @PostConstruct
    public void atStart() {
        // Test DB

        try {


        } catch (Exception ex) {
            String xs = ex.getMessage();
        }
        if (false) po.doTransaction((po, em) -> {
            //  SatGwSession sess = null;
            File file = null;
            FileInputStream f = null;
            BufferedReader bf;
            List<String> l;
            String s;

            try {


            } catch (Exception ex) {
                ex.printStackTrace();
            } finally {
                //sess.close();

            }
            return null;
        });


    }


}
