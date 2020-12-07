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

/**
 * Created by bagyenda on 20/04/2016.
 */
@Entity
@Table(name = "keycomponents")
@SequenceGenerator(name = "keycomponent", sequenceName = "keycomponent_seq", allocationSize = 1)
@JsonIgnoreProperties(value = {"hibernateLazyInitializer","key"})
@DynamicUpdate
@DynamicInsert
public class KeyComponent {
    public static final KeyComponent.Type[] suitableTS102225Types = {
            KeyComponent.Type.DES_ECB, KeyComponent.Type.DES, KeyComponent.Type.TripleDES, KeyComponent.Type
            .TripleDES_CBC, KeyComponent.Type.AES
    };
    public static final KeyComponent.Type[] suitableGPCAmmendBTypes = {
        Type.PSK_TLS
    };
    @Id
    @Column(name = "id", unique = true, nullable = false, updatable = false)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "keycomponent")
    private
    Long Id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    private
    Key key;

    @Column(name="key_type",nullable = false)
    @Enumerated(EnumType.STRING)
    private
    Type type;

    @Column(nullable = false,name="key_value", columnDefinition = "text")
    private
    String value;

    public KeyComponent() {}
    public KeyComponent(String value, Type type) {
        setValue(value);
        setType(type);
    }

    public KeyComponent(byte[] value, Type type)
    {
       this(Utils.HEX.b2H(value),type);
    }
    public Long getId() {
        return Id;
    }

    public void setId(Long id) {
        Id = id;
    }

    public Key getKey() {
        return key;
    }

    public void setKey(Key key) {
        this.key = key;
    }

    public Type getType() {
        return type;
    }

    public void setType(Type type) {
        this.type = type;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public byte[] byteValue()
    {
        try {
            return Utils.HEX.h2b(getValue());
        } catch (Exception ex) {}
        return null;
    }

    @Override
    public String toString()
    {
        return String.format("Key Component [type=%s, key=%s]", getType(),getKey());
    }

    public int to102_225_keybyte() throws Exception {
        // According to ETS TS 102 225 Sec A2, for this spec, version = key index.
        int idx = getKey().getKeyset().getVersion();   // getIndex();
        int keytype = 0;
        switch (getType()) {
            case DES:
                keytype = 0x01;
                break;
            case DES_ECB:
                keytype = 0x0C;
                break;
            case TripleDES_CBC:
                byte[] kv = byteValue();
                keytype = kv.length == 16 ? 0x05 : 0x09;
                break;
            case AES:
                keytype = 0x02; // Appendix D of SGP.11 v4.1
                break;
            default:
                keytype = 0x3;
                break;
        }
        return ((idx << 4) | keytype) & 0xFF;
    }

    // Integer values are from Table 11.1.8 of GPC v2.3 & Table 3-1 of GPC Ammendment B.
    public  enum Type {
        RFU(0), DES(0x80),
        TripleDES(0x81),
        TripleDES_CBC(0x82),
        DES_ECB(0x83),
        DES_CBC(0x84),
        PSK_TLS(0x85),
        AES(0x88),
        HMAC_SHA1(0x90),
        HMAC_SHA1_160(0x91),
        RSA_PK_e(0xA0),
        RSA_PK_N(0xA2),
        RSA_SK_N(0xA3),
        RSA_SK_d(0xA4),
        RSA_SK_P(0xA5),
        RSA_SK_Q(0xA5),
        RSA_SK_PQ(0xA6),
        RSA_SK_DP1(0xA7),
        RSA_SK_DQ1(0xA8),
        GPC_Extended(0xFF),
        ECC_PK(0xB0), // These are from GPC_2.2 Ammendment E
        ECC_SK(0xB1),
        ECC_Pp(0xB2),
        ECC_Ap(0xB3),
        ECC_Bp(0xB4),
        ECC_Gp(0xB5),
        ECC_Np(0xB6),
        ECC_kp(0xB7),
        ECC_KeyRef(0xF0);

        private int value;
        Type(int val)
        {
            this.value = val;
        }
        private static final Type[] vals = values();
        public static KeyComponent.Type fromString(String val)  {
            int x = Integer.parseInt(val, 16);
            for (Type t: vals)
             if (t.value == x)
                 return t;
            return RFU;
        }

        @Override
        public String toString() {
            return String.format("%02X", toInt());
        }

        public int toInt()
        {
            return value;
        }
    }
}
