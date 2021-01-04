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
import io.njiwa.dp.model.ISDP;
import io.njiwa.sr.model.SecurityDomain;
import io.njiwa.sr.ws.types.Eis;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by bagyenda on 20/04/2016.
 */
@Entity
@Table(name = "keysets", uniqueConstraints = {
        @UniqueConstraint(columnNames = {"version", "sd_id"}, // Version must be unique in SD. Right?!
                name = "keyset_idx_ct")
}, indexes = {
        @Index(columnList = "version,sd_id", name = "keysets_idx1")
})
@SequenceGenerator(name = "keysets", sequenceName = "keysets_seq", allocationSize = 1)
@JsonIgnoreProperties(value = {"hibernateLazyInitializer", "keyset"})
@DynamicUpdate
@DynamicInsert
public class KeySet {

    @javax.persistence.Id
    @Column(name = "id", unique = true, nullable = false, updatable = false)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "keysets")
    private
    Long Id;

    @Column(nullable = false)
    private
    Integer version; // Should normally match type

    @Column(nullable = false, name = "ks_type")
    @Enumerated(EnumType.STRING)
    private
    Type type;

    @Column(nullable = false, columnDefinition = "bigint not null default 0", insertable = false)
    private
    Long counter;

    @OneToMany(mappedBy = "keyset", cascade = CascadeType.ALL,orphanRemoval = true)
    private
    List<Certificate> certificates;

    @OneToMany(mappedBy = "keyset", cascade = CascadeType.ALL,orphanRemoval = true)
    private
    List<Key> keys;

    @ManyToOne(fetch = FetchType.LAZY, optional = true)
    private
    SecurityDomain sd; // Map to SM-SR Security Domain, if this is owned by the SM-SR

    @ManyToOne(fetch = FetchType.LAZY, optional = true)
    private
    ISDP isdp; // Map to SM-DP ISD-P, if this is owned by the SM-DP

    public KeySet() {
    }

    public KeySet(int version, Type type, List<Certificate> certificates, List<Key> keys, long counter) {
        setVersion(version);
        setType(type);

        try {
            for (Certificate c : certificates)
                c.setKeyset(this);
        } catch (Exception ex) {
        }
        try {
            for (Key k : keys)
                k.setKeyset(this);
        } catch (Exception ex) {
        }
        setCertificates(certificates);
        setKeys(keys);
        setCounter(counter);
    }

    public KeySet(int version, Key key1, Type type, long counter)
    {
        setVersion(version);
        List<Key> l = new ArrayList<>();
        l.add(key1);
        setKeys(l);
        key1.setKeyset(this);
        setCounter(counter);
        setType(type);
    }

    public KeySet(String version, Eis.SecurityDomain.KeySet.Type wsType, List<Certificate> certificates, List<Key>
            keys, long counter) {
        this(Integer.parseInt(version, 10),
                Type.fromWsType(wsType),
                certificates,
                keys,
                counter);
    }

    public long bumpCounter(EntityManager em) throws Exception {


        em.lock(this, LockModeType.PESSIMISTIC_WRITE); // Better?
        long ctr = getCounter() + 1;
        setCounter(ctr);
        em.flush(); // Needed??
        return ctr;
    }

    @Override
    public String toString() {
        return String.format("KeySet [version=%02x,type=%s]", getVersion(), getType());
    }

    public Long getId() {
        return Id;
    }

    public void setId(Long id) {
        Id = id;
    }

    public Integer getVersion() {
        return version;
    }

    public void setVersion(Integer version) {
        this.version = version;
    }

    public Type getType() {
        return type;
    }

    public void setType(Type type) {
        this.type = type;
    }

    public List<Certificate> getCertificates() {
        return certificates;
    }

    public void setCertificates(List<Certificate> certificates) {
        this.certificates = certificates;
    }

    public List<Key> getKeys() {
        return keys;
    }

    public void setKeys(List<Key> keys) {
        this.keys = keys;
    }

    public SecurityDomain getSd() {
        return sd;
    }

    public void setSd(SecurityDomain sd) {
        this.sd = sd;
    }

    public Long getCounter() {
        return counter;
    }

    public void setCounter(Long counter) {
        this.counter = counter;
    }

    // Map to SD

    public Type keysetType() {
        if (getType() != null)
            return getType();
        else
            return Type.fromVersion(getVersion());
    }

    public ISDP getIsdp() {
        return isdp;
    }

    public void setIsdp(ISDP isdp) {
        this.isdp = isdp;
    }

    public enum Type {
        SCP03, SCP80, SCP81, TokenGeneration, ReceiptVerification, CA;

        public static Type fromVersion(int version) {
            // Table 4-1 of GPC SE Configuration 1.0
            if (version >= 0x01 && version <= 0x0F)
                return SCP80; // Table A1 of ETS TS 102 225
            if (version >= 0x30 && version <= 0x3F)
                return SCP03;
            else if (version >= 0x40 && version <= 0x4F)
                return SCP81;

            switch (version) {
                case 0x71:
                    return ReceiptVerification;
                case 0x70:
                    return TokenGeneration;
                default:
                    return SCP80;
            }
        }

        public Utils.Pair<Integer, Integer> versionLimits() {
            int min, max;
            switch (this) {
                case SCP80:
                    min = 0x01;
                    max = 0x0F;
                    break;
                case SCP03:
                    min = 0x30;
                    max = 0x3F;
                    break;
                case SCP81:
                    min = 0x40;
                    max = 0x4F;
                    break;
                case ReceiptVerification:
                    min = max = 0x71;
                    break;
                case TokenGeneration:
                    min = max = 0x70;
                    break;
                default:
                    min = 0x50;
                    max = 0x6F;
                    break;
            }
            return new Utils.Pair<>(min, max);
        }

        public static Type fromWsType(Eis.SecurityDomain.KeySet.Type t) { // A bit silly really
            switch (t) {
                case SCP03:
                    return SCP03;
                case SCP80:
                    return SCP80;
                case SCP81:
                    return SCP81;
                case TokenGeneration:
                    return TokenGeneration;
                case ReceiptVerification:
                    return ReceiptVerification;
                case CA:
                    return CA;
                default:
                    return SCP03;
            }
        }

        public static Eis.SecurityDomain.KeySet.Type toWsType(Type t) { // A bit silly really
            switch (t) {
                case SCP03:
                    return Eis.SecurityDomain.KeySet.Type.SCP80;
                case SCP80:
                    return Eis.SecurityDomain.KeySet.Type.SCP80;
                case SCP81:
                    return Eis.SecurityDomain.KeySet.Type.SCP81;
                case TokenGeneration:
                    return Eis.SecurityDomain.KeySet.Type.TokenGeneration;
                case ReceiptVerification:
                    return Eis.SecurityDomain.KeySet.Type.ReceiptVerification;
                case CA:
                    return Eis.SecurityDomain.KeySet.Type.CA;
                default:
                    return Eis.SecurityDomain.KeySet.Type.SCP03;
            }
        }
    }

}
