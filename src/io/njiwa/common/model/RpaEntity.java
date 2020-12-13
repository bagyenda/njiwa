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
import io.njiwa.common.ECKeyAgreementEG;
import io.njiwa.common.PersistenceUtility;
import io.njiwa.common.ServerSettings;
import io.njiwa.common.Utils;
import org.apache.commons.net.util.SubnetUtils;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;

import javax.naming.ldap.Rdn;
import javax.persistence.*;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @brief Represents a Remote Provisioning Architecture Entity (See Figure 1 in SGP v3.0)
 * <p>
 * Before saving to DB, we probably do NOT need to verify the certificate against the issuer, right?
 * What's in our trust store are all potential CIs. Right?
 */
@Entity
@Table(name = "rpa_entities",
        indexes = {@Index(columnList = "entity_oid,entity_type", name = "rpa_entity_idx1", unique = true),
        @Index(columnList = "x509subject,entity_type", name = "rpa_entity_idx2", unique = true),
                @Index(columnList = "date_added"
        , name = "rpa_entity_idx3"),
                @Index(columnList = "wsuserid,entity_type", name = "rpa_entity_idx4", unique = true),
        @Index(columnList = "dns_name", name="rpa_entity_idx5", unique = true)})
@SequenceGenerator(name = "rpa_entity", sequenceName = "rpa_entities_seq", allocationSize = 1)
@JsonIgnoreProperties(value = {"hibernateLazyInitializer", "wskeyStoreAlias", "sMkeyStoreAlias"})
@DynamicUpdate
@DynamicInsert
public class RpaEntity {
    public static final long LOCAL_ENTITY_ID = -1;

    private static final long serialVersionUID = 1L;
    private static final Random RANDOM = new SecureRandom();

    // For sorting DNs
    private static final Map<String, Integer> rdnOrder = new ConcurrentHashMap<String,Integer>() {{
        put("CN", 1);
        put("L", 2);
        put("ST", 3);
        put("O", 4);
        put("OU", 5);
        put("C", 6);
        put("STREET", 7);
        put("DC", 8);
        put("UID", 9);
    }};
    private static final Comparator<Rdn> rdnCompare = (Rdn o1, Rdn o2) -> {

        int x1, x2;
        int notFound = 0;
        try {
            x1 = rdnOrder.get(o1.getType());
        } catch (Exception ex) {
            x1 = 100;
            notFound++;
        }
        try {
            x2 = rdnOrder.get(o2.getType());
        } catch (Exception ex) {
            x2 = 100;
            notFound++;
        }
        if (notFound > 1)
            return o1.getType().compareTo(o2.getType()); // Order lexicographically if both not on our list.
        return x1 - x2;
    };

    @javax.persistence.Id
    @Column(name = "id", unique = true, nullable = false, updatable = false)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "rpa_entity")
    private Long Id;
    @Column(nullable = false, name = "date_added", columnDefinition = "timestamp default current_timestamp",
            updatable = false, insertable = false)
    private Date dateAdded; //<! Date this entity was added
    @Column(nullable = false, name = "entity_type")
    @Enumerated(EnumType.STRING)
    private Type type; //!< Type of entity (MNO, EUM, etc)
    @Column(nullable = true, columnDefinition = "TEXT")
    private String description; //!< Free-form description

    @Column(name = "entity_oid", nullable = false, columnDefinition = "TEXT")
    private String oid; //!< The OID is a unique string (ASN.1 OID format) that is used to identify the entity
    // world-wide
    @Column(columnDefinition = "TEXT")
    private String x509Subject; //!< This is the X.509 certificate's subject field. It is extracted from the
    // certificate itself

    @Column(columnDefinition = "TEXT")
    private String x509SKI; //!< The subject key identifier, hex-coded...

    //!< This is the dns name. Must be unique
    @Column(nullable = false, columnDefinition = "TEXT", unique = true, name = "dns_name")
    private String dns_name;

    @Column(nullable = false, columnDefinition = "TEXT", name="admin_user")
    private String admin_user;

    @Column(nullable = true, columnDefinition = "TEXT")
    private String wskeyStoreAlias; //!< The alias in the java keystore, this is the key used for Web Service
    // authentication.
    // Extracted by the module

    @Column(nullable = true, columnDefinition = "TEXT", name="smprivatekeyalias")
    private String secureMessagingPrivateKeyAlias; //!< The Secure Messaging alias in the java keystore, this is the key used for

    @Column(nullable = true, columnDefinition = "TEXT", name="smcertalias")
    private String secureMessagingCertificateAlias;

    // authenticating to the euICC (e.g. by SM-DP or SM-SR). This is also extracted by the server
    @Column(columnDefinition = "TEXT")
    private String es1URL; //!< The URL on which to contact this entity for ES1 Web service calls
    @Column(columnDefinition = "TEXT")
    private String es2URL; //!< The URL on which to contact this entity for ES2 Web service calls
    @Column(columnDefinition = "TEXT")
    private String es3URL; //!< The URL on which to contact this entity for ES3 Web service calls
    @Column(columnDefinition = "TEXT")
    private String es4URL; //!< The URL on which to contact this entity for ES4 Web service calls
    @Column(columnDefinition = "TEXT")
    private String es7URL; //!< The URL on which to contact this entity for ES7 Web service calls
    @Column
    private String wSuserid; //!< Userid for incoming Web Service authentication. May be NULL.
    @Column
    private String wSpassword; //!< The password, for web service authentication. Might be NULL.
    @Column
    @Enumerated(EnumType.STRING)
    private OutgoingAuthMethod outgoingAuthMethod; //!< How to authenticate to remote entity (user/pass or certificate)
    @Column
    private String outgoingWSuserid; //!< User name for outgoing web service calls authentication
    @Column
    private String outgoingWSpassword; //!< Outgoing password
    // certificate data
    @Column
    private byte[] additionalDiscretionaryData; //!< Discretionary data as per GPC Ammendment E. This is extracted from the
    // certificate
    // data
    @Column(columnDefinition = "Additional discretionary data TLVs")
    private byte[] signature; //!< Public key signature according to GPC Ammendment E and SGP v3.1. This is extract
    // from the
    // certificate date


    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "rpa_entities_allowed_ips")
    @Column(name = "ip", columnDefinition = "TEXT NOT NULL")
    private Set<String> allowedIPs; //!< If our server acts as this entity, then we may also allow/prevent certain
    // client IPs
    // from accessing the server. See also below

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "rpa_entities_denied_ips")
    @Column(name = "ip", columnDefinition = "TEXT NOT NULL")
    private Set<String> deniedIPs; //!< client IPs that may not access this server
    // XXX For now we ignore the Nonce re-use check. We only check that timestamp is within X hrs of ours.
    @Transient
    private X509Certificate cert;

    public RpaEntity() {
    }


    public RpaEntity(Type type, String wskeyStoreAlias, String secureMessagingPrivateKeyAlias, String oid, byte[] additionalDiscretionaryData, byte[] signature, String x509Subject) {
        setType(type);
        setWskeyStoreAlias(wskeyStoreAlias);
        setAdditionalDiscretionaryData(additionalDiscretionaryData);
        setX509Subject(x509Subject);

        setsSecureMessagingPrivateKeyAlias(secureMessagingPrivateKeyAlias);
        setSignature(signature);

        setOid(oid);
    }

    public static RpaEntity getByDNS(EntityManager em, String dns_name)  {
        return em.createQuery("from RpaEntity  where  dns_name = :n", RpaEntity.class)
                .setParameter("n", dns_name)
                .getSingleResult();
    }

    public static RpaEntity getByUserId(EntityManager em, String userid, Type type) {
        return em.createQuery("from RpaEntity WHERE wSuserid = :u and type = :t", RpaEntity.class).setParameter("t",
                type).setParameter("u", userid).setMaxResults(1).getSingleResult();
    }

    public static RpaEntity getByUserId(EntityManager em, String userid) throws Exception {
        return em.createQuery("from RpaEntity WHERE wSuserid = :u", RpaEntity.class).setParameter("u", userid).setMaxResults(1).getSingleResult();
    }

    public static RpaEntity getEntityByWSKeyAlias(EntityManager em, String wsKeystoreAlias, Type type) throws Exception {
        return em.createQuery("from RpaEntity WHERE wskeyStoreAlias = :u and type = :t", RpaEntity.class).setParameter("t", type).setParameter("u", wsKeystoreAlias).setMaxResults(1).getSingleResult();
    }

    // XXX We need a better way to canonicalise the subjects
    // This is used by EUM verify EIS signature
    public static X509Certificate getCertificateBySubject(EntityManager em, String x509Subject) {
       try {
           RpaEntity rpaEntity = em.createQuery("from RpaEntity WHERE x509Subject = :s", RpaEntity.class)

                   .setParameter("s", x509Subject).setMaxResults(1).getSingleResult();
           return rpaEntity.secureMessagingCert();
       } catch (Exception ex) {
           return null;
       }
    }

    public static X509Certificate getCertificateBySKI(EntityManager em, byte[] x509SKI) {
        try {
            String ski = Utils.HEX.b2H(x509SKI);
            RpaEntity rpaEntity = em.createQuery("from RpaEntity WHERE x509SKI = :s", RpaEntity.class)

                    .setParameter("s", ski).setMaxResults(1).getSingleResult();
            return rpaEntity.secureMessagingCert();
        } catch (Exception ex) {
            return null;
        }
    }


    public void updateInterfaceUris(String prefix)
    {
        setEs1URL(prefix + "/SMSR/ES1");
        setEs2URL(prefix + "/SMDP/ES2");
        setEs3URL(prefix + "/SMDP/ES3");
        setEs4URL(prefix + "/SMSR/ES4");
        setEs7URL(prefix + "/SMSR/ES7");
    }

    public static RpaEntity getByOID(EntityManager em, String oid, Type type) {
        try {
            return em.createQuery("from RpaEntity WHERE oid = :s and type = :t", RpaEntity.class).setParameter("t",
                    type).setParameter("s", oid).setMaxResults(1).getSingleResult();
        } catch (Exception ex) {
        }
        return null;
    }

    public static RpaEntity getByOID(PersistenceUtility po, final String oid, final Type type) {
        return po.doTransaction((PersistenceUtility xpo, EntityManager em) ->
                 getByOID(em, oid, type)
            );
    }

    private static RpaEntity makeLocalEntity(Type type) throws Exception {
        Utils.Pair<String,X509Certificate> p  = ServerSettings.getServerCertAndAlias();
        String x509Subject = p.l.getSubjectDN().getName();
        String keyAlias = p.k;
        String  smKeyAlias = ServerSettings.getServerEcdsaSecretKeyAlias();
        byte[] additionalDiscretionaryDataTlvs = ServerSettings.getAdditionalDiscretionaryDataTlvs();
        byte[] sig = type == Type.SMDP ? ServerSettings.getSMDPSignedData() : ServerSettings.getSMSRSignedData();
        RpaEntity rpa = new RpaEntity(type,null,smKeyAlias,
                ServerSettings.getOid(type), additionalDiscretionaryDataTlvs,sig,x509Subject);
        rpa.setSecureMessagingCertificateAlias(keyAlias);
        rpa.updateInterfaceUris(ServerSettings.getBasedeploymenturi());
        rpa.setId(LOCAL_ENTITY_ID); // Make it as local...
        return rpa;
    }
    public static RpaEntity getlocalSMDP() throws Exception {
        return makeLocalEntity(Type.SMDP);
    }

    public static RpaEntity getlocalSMSR() throws Exception {
        return makeLocalEntity(Type.SMSR);
    }

    public static RpaEntity getLocal(Type type) {
        try {
            return makeLocalEntity(type);
        } catch (Exception ex) {
            String xs = ex.getMessage();
        }
        return null;
    }

    public static X509Certificate getWSCertificateByOID(EntityManager em, String oid, Type type) throws Exception {
        RpaEntity rpaEntity = getByOID(em, oid, type);
        String alias = rpaEntity.getWskeyStoreAlias();
        return (X509Certificate) Utils.getKeyStore().getCertificate(alias);
    }

    public void updateCertInfo(X509Certificate cert)
    {
        setX509Subject(cert.getSubjectDN().getName());
        byte[] subjectIdentifier = ECKeyAgreementEG.getCertificateSubjectKeyIdentifier(cert);
        if (subjectIdentifier != null)
            setX509SKI(Utils.HEX.b2H(subjectIdentifier));
    }

    public boolean isAllowedIP(String ip) {
        Set<String> allowed = getAllowedIPs();
        Set<String> denied = getDeniedIPs();


        // Test allowed first
        if (allowed != null && allowed.size() > 0) {
            for (String net : allowed)
                try {
                    if (new SubnetUtils(net).getInfo().isInRange(ip)) return true;
                } catch (Exception ex) {
                }

            return false;
        }

        try {
            // Test denied, but it is not binding
            for (String net : denied)
                try {
                    if (new SubnetUtils(net).getInfo().isInRange(ip)) return false;
                } catch (Exception ex) {
                }
        } catch (Exception ex) {
        }

        return true;
    }

    private boolean checkIP(String ipNet) {
        try {
            new SubnetUtils(ipNet);
        } catch (Exception ex) {
            return false;
        }
        return true;
    }

    public void updateIPpermissions(String[] allowedIps, String[] deniedIps) {
        List<String> l = new ArrayList<>();
        try {
            for (String ipNet : allowedIps)
                if (checkIP(ipNet)) l.add(ipNet);
        } catch (Exception ex) {
        }
        setAllowedIPs(new HashSet<>(l));

        l.clear();
        try {
            for (String ipNet : deniedIps)
                if (checkIP(ipNet)) l.add(ipNet);
        } catch (Exception ex) {
        }
        setDeniedIPs(new HashSet<>(l));
    }

    public String makeKeyStoreAlias(String stype) {
        byte[] data = new byte[6];
        RANDOM.nextBytes(data);
        String alias = String.format("%s-%s-%s-%s", getType(), stype, getDns_name(), Utils.HEX.b2H(data));
        return alias;
    }

    public ECPrivateKey secureMessagingPrivKey() throws Exception {
        String alias = getsSecureMessagingPrivateKeyAlias();
        return Utils.getServerECPrivateKey(alias);
    }

    public Long getId() {
        return Id;
    }

    public void setId(Long id) {
        Id = id;
    }

    public Date getDateAdded() {
        return dateAdded;
    }

    public void setDateAdded(Date dateAdded) {
        this.dateAdded = dateAdded;
    }

    public Type getType() {
        return type;
    }

    public void setType(Type type) {
        this.type = type;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getOid() {
        return oid;
    }

    public void setOid(String oid) {
        this.oid = oid;
    }

    public String getX509Subject() {
        return x509Subject;
    }

    public void setX509Subject(String x509Subject) {
        this.x509Subject = x509Subject;
    }

    public String getEs1URL() {
        return es1URL;
    }

    public void setEs1URL(String url) {
        this.es1URL = url;
    }

    public String getEs2URL() {
        return es2URL;
    }

    public void setEs2URL(String es2URL) {
        this.es2URL = es2URL;
    }

    public String getEs3URL() {
        return es3URL;
    }

    public void setEs3URL(String es3URL) {
        this.es3URL = es3URL;
    }

    public String getEs4URL() {
        return es4URL;
    }

    public void setEs4URL(String es4URL) {
        this.es4URL = es4URL;
    }

    public String getEs7URL() {
        return es7URL;
    }

    public void setEs7URL(String es7URL) {
        this.es7URL = es7URL;
    }

    public String getWskeyStoreAlias() {
        return wskeyStoreAlias;
    }

    public void setWskeyStoreAlias(String keyStoreAlias) {
        this.wskeyStoreAlias = keyStoreAlias;
    }

    // Fixup alias
    @PrePersist
    @PreUpdate
    private void fixupAlias() {
        String x509Subject = getX509Subject();
        if (x509Subject == null)
            try {
            // fix it up.
            X509Certificate certificate = (X509Certificate)Utils.getKeyStore().getCertificate(getSecureMessagingCertificateAlias());
            x509Subject = certificate.getSubjectDN().getName();
                setX509Subject(x509Subject);
        } catch (Exception ex) {
            String xs = ex.getMessage();
        }

    }

    public String getwSuserid() {
        return wSuserid;
    }

    public void setwSuserid(String wSuserid) {
        this.wSuserid = wSuserid;
    }

    public String getwSpassword() {
        return wSpassword;
    }

    public void setwSpassword(String wSpassword) {
        this.wSpassword = wSpassword;
    }

    public String urlForInterface(String inter) {
        try {
            if (inter.contains("1")) return getEs1URL();
            else if (inter.contains("2")) return getEs2URL();
            else if (inter.contains("3")) return getEs3URL();
            else if (inter.contains("4")) return getEs4URL();
            else if (inter.contains("7")) return getEs7URL();
        } catch (Exception ex) {

        }
        return null;
    }

    public OutgoingAuthMethod getOutgoingAuthMethod() {
        return outgoingAuthMethod;
    }

    public void setOutgoingAuthMethod(OutgoingAuthMethod outgoingAuthMethod) {
        this.outgoingAuthMethod = outgoingAuthMethod;
    }

    public String getOutgoingWSuserid() {
        return outgoingWSuserid;
    }

    public void setOutgoingWSuserid(String outgoingWSuserid) {
        this.outgoingWSuserid = outgoingWSuserid;
    }

    public String getOutgoingWSpassword() {
        return outgoingWSpassword;
    }

    public void setOutgoingWSpassword(String outgoingWSpassword) {
        this.outgoingWSpassword = outgoingWSpassword;
    }

    public X509Certificate secureMessagingCert() {
        if (cert == null) try {
            String alias = getSecureMessagingCertificateAlias();
            cert = (X509Certificate) Utils.getKeyStore().getCertificate(alias);
        } catch (Exception ex) {
        }
        return cert;
    }

    public String getsSecureMessagingPrivateKeyAlias() {
        return secureMessagingPrivateKeyAlias;
    }

    public void setsSecureMessagingPrivateKeyAlias(String sMkeyStoreAlias) {
        this.secureMessagingPrivateKeyAlias = sMkeyStoreAlias;
    }

    public byte[] getAdditionalDiscretionaryData() {
        return additionalDiscretionaryData;
    }

    public void setAdditionalDiscretionaryData(byte[] discretionaryData) {
        this.additionalDiscretionaryData = discretionaryData;
    }

    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    public Set<String> getAllowedIPs() {
        return allowedIPs;
    }

    public void setAllowedIPs(Set<String> allowedIPs) {
        this.allowedIPs = allowedIPs;
    }

    public Set<String> getDeniedIPs() {
        return deniedIPs;
    }

    public void setDeniedIPs(Set<String> deniedIPs) {
        this.deniedIPs = deniedIPs;
    }

    @Transient
    public Boolean getHasWsKey()
    {
        return getWskeyStoreAlias() != null;
    }

    public String getDns_name() {
        return dns_name;
    }

    public void setDns_name(String dns_name) {
        this.dns_name = dns_name;
    }

    public String getAdmin_user() {
        return admin_user;
    }

    public void setAdmin_user(String admin) {
        this.admin_user = admin;
    }

    public String getSecureMessagingCertificateAlias() {
        return secureMessagingCertificateAlias;
    }

    public void setSecureMessagingCertificateAlias(String secureMessagingCertificateAlias) {
        this.secureMessagingCertificateAlias = secureMessagingCertificateAlias;
    }

    public String getX509SKI() {
        return x509SKI;
    }

    public void setX509SKI(String x509SKI) {
        this.x509SKI = x509SKI;
    }

    public enum Type {
        MNO, SMDP, SMSR, EUM, CI, M2MSP; // But can we have multiple CIs? No

        private static Type[] xvalues = values();

        public static Type fromString(String val) {
            try {
                for (Type t : xvalues)
                    if (t.toString().equals(val)) return t;
            } catch (Exception ex) {
            }
            return null;
        }
    }

    /**
     * @brief style of out-going authentication
     */
    public enum OutgoingAuthMethod {
        USER, CERT;


        private static OutgoingAuthMethod[] xvalues = values();

        public static OutgoingAuthMethod fromString(String val) {
            try {
                for (OutgoingAuthMethod t : xvalues)
                    if (t.toString().equals(val)) return t;
            } catch (Exception ex) {
            }
            return null;
        }
    }
}
