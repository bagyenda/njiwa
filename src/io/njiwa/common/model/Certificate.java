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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.njiwa.common.Utils;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;

import javax.persistence.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PushbackInputStream;
import java.text.SimpleDateFormat;
import java.util.Date;

import static io.njiwa.common.ECKeyAgreementEG.*;

/**
 * Created by bagyenda on 20/04/2016.
 */
@Entity
@Table(name = "certificates", indexes = {@Index(columnList = "idx,keyset_id", name = "cert_idx1")})
@SequenceGenerator(name = "certificates", sequenceName = "certificate_seq", allocationSize = 1)
@JsonIgnoreProperties(value = {"hibernateLazyInitializer", "keyset"})
@DynamicUpdate
@DynamicInsert
public class Certificate {
    public static final String BASE_OID = "1.3.6.1.4.1";
    public static final String SM_DP_DISCRETIONARY_DATA_EXTENSION_OID = BASE_OID + ".1.1";
    public static final String SM_DP_CERT_SIGNATURE_EXTENSION_OID = BASE_OID + ".1.2";
    public static final String CI_KEY_PARAM_TYPE_REFERENCE_EXTENSION_OID = BASE_OID + ".1.3";

    public static final String CI_CERTIFICATE_ALIAS = "ci";
    public static final String LOCAL_SM_SR_KEYSTORE_ALIAS = "sm-sr-local";
    public static final String LOCAL_SM_DP_KEYSTORE_ALIAS = "sm-dp-local";

    @javax.persistence.Id
    @Column(name = "id", unique = true, nullable = false, updatable = false)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "certificates")
    private Long Id;

    @Column(nullable = false, name = "idx")
    private Integer index;

    @Column(nullable = false, columnDefinition = "text")
    private String caId; // CA Identifier

    @Column(nullable = false, name = "certificate", columnDefinition = "text")
    private String value;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    private KeySet keyset; // Upward link

    public Certificate() {
    }

    public Certificate(String value, String caId, int index) {
        setValue(value);
        setCaId(caId);
        setIndex(index);
    }

    public Long getId() {
        return Id;
    }

    public void setId(Long id) {
        Id = id;
    }

    public Integer getIndex() {
        return index;
    }

    public void setIndex(Integer index) {
        this.index = index;
    }

    public String getCaId() {
        return caId;
    }

    public void setCaId(String ca_id) {
        this.caId = ca_id;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public KeySet getKeyset() {
        return keyset;
    }

    public void setKeyset(KeySet keyset) {
        this.keyset = keyset;
    }

    public static class Data {
        public static final int KEYAGREEMENT = 0x0080; // Table 23 of SGP v3.1
        public String serial;
        public String CaIIN;
        public int keyUsage;
        public byte[] discretionaryData;
        public byte[] publicKeyQ;
        public byte[] publicKeyFull;
        public byte[] publicKeyMod;
        public int publicKeyReferenceParam;
        public String subjectIdentifier;
        public Date effectiveDate;
        public Date expireDate;
        public String ecasdImageNumber;

        public byte[] signature;

        /**
         * @param data
         * @return
         * @throws Exception
         * @brief decode as per Table 23,24 of SGP.02 v4.2. According to GPC Ammendment A, this data is TLV encoded.
         * Some items have two-byte tags.
         */
        public static Data decode(String data) throws Exception {
            Data d = new Data();
            ByteArrayInputStream inputStream = new ByteArrayInputStream(Utils.HEX.h2b(data));
            byte[] x = Utils.BER.decodeTLV(inputStream, GPC_A_CERTIFICATE_TAG);

            ByteArrayInputStream in = new ByteArrayInputStream(x);

            while (in.available() > 0) {
                in.mark(1);
                int ch = 0xFF & in.read();

                in.reset(); // Go back...
                byte[] xdata;
                int tag;

                /**
                 * Look for 5F25, 5F24, 5F20, 5F37 and 7F49 TLVs first.
                 */
                boolean twoByteTag = (ch == 0x5F || ch == 0x7F);

                Utils.Pair<InputStream, Integer> xres = Utils.BER.decodeTLV(in, twoByteTag);
                xdata = Utils.getBytes(xres.k);
                tag = xres.l;

                switch (tag) {
                    case 0x93:
                        d.serial = Utils.HEX.b2H(xdata);
                        break;
                    case 0x42:
                        d.CaIIN = Utils.HEX.b2H(xdata);
                        break;
                    case 0x5F20:
                        d.subjectIdentifier = Utils.HEX.b2H(xdata);
                        break;
                    case 0x95:

                        d.keyUsage = ((xdata[0] &0xFF) << 8) | xdata[1] &0xFF;
                        break;
                    case 0x5F25:
                        try {
                            String y = Utils.HEX.b2H(xdata);
                            d.effectiveDate = new SimpleDateFormat("yyMMdd").parse(y);

                        } catch (Exception ex) {
                        }
                        break;
                    case 0x5F24:
                        try {
                            String y = Utils.HEX.b2H(xdata);
                            d.expireDate = new SimpleDateFormat("yyMMdd").parse(y);
                        } catch (Exception ex) {
                        }
                        break;
                    case 0x45:
                        d.ecasdImageNumber = Utils.HEX.b2H(xdata);
                        break;
                    case 0x53:
                    case 0x73:
                        d.discretionaryData = xdata;
                        break;
                    case 0x7F49:
                        d.publicKeyFull = xdata;
                        InputStream xin = new ByteArrayInputStream(xdata);
                        try {
                            // Parse public key
                            d.publicKeyQ = Utils.BER.decodeTLV(xin, (short)0xB0);
                            d.publicKeyReferenceParam = Utils.BER.decodeTLV(xin, (short)0xF0)[0]; // Read the key ref param
                        } catch (Exception ex) {
                        }
                        break;
                    case 0x5F38:
                        d.publicKeyMod = xdata; // Store directly
                        break;
                    case 0x5F37:
                    case 0x9E: // According to Table F-2 of GPC v2.3
                        d.signature = xdata;
                        break;
                    default:
                        // ignore
                        break;
                }
            }
            return d;
        }

        public byte[] makeCertificateSigData() {
            try {
                // We assume Table 11-3 of GPC UICC Configuration v1.0
                return new ByteArrayOutputStream() {
                    {
                        Utils.BER.appendTLV(this, SGP02_PUBLIC_KEY_TAG, publicKeyFull);
                        Utils.BER.appendTLV(this, (short) 0x93, Utils.HEX.h2b(serial));
                        Utils.BER.appendTLV(this, (short) 0x42, Utils.HEX.h2b(CaIIN));
                        Utils.BER.appendTLV(this, GPC_A_SUBJECT_IDENTIFIER_TAG, Utils.HEX.h2b(subjectIdentifier));
                        if (effectiveDate != null)
                            Utils.BER.appendTLV(this, GPC_A_CERT_EFFECTIVE_DATE_TAG,
                                    Utils.HEX.h2b(new SimpleDateFormat("yyyyMMdd").format(effectiveDate)));
                        Utils.BER.appendTLV(this, GPC_A_CERT_EXPIRY_DATE_TAG, Utils.HEX.h2b(new SimpleDateFormat(
                                "yyyyMMdd").format(expireDate)));
                        if (discretionaryData != null) Utils.BER.appendTLV(this, (short) 0x53, discretionaryData);
                    }
                }.toByteArray();
            } catch (Exception ex) {
            }
            return null;
        }
    }

}
