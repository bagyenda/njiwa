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

package io.njiwa.sr.ws.types;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.njiwa.common.Utils;
import io.njiwa.common.model.KeyComponent;
import io.njiwa.common.model.RpaEntity;
import io.njiwa.common.ws.types.BaseResponseType;
import io.njiwa.common.ws.types.RpsElement;

import javax.xml.bind.annotation.*;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import java.util.*;

/**
 * Created by bagyenda on 04/05/2016.
 */
@XmlRootElement(namespace = "http://namespaces.gsma.org/esim-messaging/1")
public class Eis implements RpsElement {

    @XmlElement(name = "EumSignedInfo")
    public EumSignedInfo signedInfo;

    // According to SGP.11 v4.1 this should have this name, W3 spec says otherwise.
    @XmlElement(name = "EumSignature", namespace = "http://www.w3.org/2000/09/xmldsig#")
    public Signature sig;

    @XmlElement(name = "RemainingMemory")
    public long remainingMemory;
    @XmlElement(name = "AvailableMemoryForProfiles")
    public long availableMemoryForProfiles;
    @XmlElement(name = "lastAuditDate")
    public String lastAudit;
    @XmlElement(name = "Smsr-id")
    public String smsrId;

    @XmlElement(name = "EumCertificateId")
    public String eumCertificateId;

    @XmlElement(name="ProfileInfo")
    List<ProfileInfo> profiles;

    @XmlElement(name = "Isd-r")
    public SecurityDomain isdR;

    @XmlElement(name = "AuditTrail")
    public AuditTrail auditTrail;

    @XmlElement(name = "AdditionalProperties")
    AdditionalProperties properties;

    public void hideNotificationFields() {
        // Annex E of SGP 02 v3.1, hide some fields
        signedInfo.eumId = null;
        signedInfo.productionDate = null;
        signedInfo.platformType = null;
        signedInfo.platformType = null;
        remainingMemory = 0;
        availableMemoryForProfiles = 0;
        lastAudit = null;
        smsrId = null;
        signedInfo.isdPLoadFileAid = null;
        signedInfo.isdPModuleAid = null;
        signedInfo.ecasd = null;
        isdR = null;
        auditTrail = null;
        signedInfo.euiCCCapabilities = null;
        sig = null;
        eumCertificateId = null;
        try {
            for (ProfileInfo p : profiles)
                p.hideNotificationFields();
        } catch (Exception ex) {
        }
    }

    public void hideCurrentKeys() {
        try {
            isdR.keySets = new ArrayList<>();
        } catch (Exception ex) {
        }
    }

    public void hideGetEISFields(String requestor, RpaEntity.Type type) {
        lastAudit = null;
        auditTrail = null;
        if (type == RpaEntity.Type.MNO) {
            signedInfo.isdPLoadFileAid = null;
            signedInfo.isdPModuleAid = null;
            isdR = null;
            signedInfo.ecasd = null;
            List<ProfileInfo> pl = new ArrayList<>();
            try {
                // Remove all but those for this mno
                for (ProfileInfo p : profiles)
                    if (p.mno_id != null && p.mno_id.equals(requestor))
                        pl.add(p);
                profiles = pl;
            } catch (Exception ex) {
            }
        } else {
            profiles = new ArrayList<>(); // Don't show profiles
            if (isdR != null) {
                // Hide keys
                isdR.keySets = new ArrayList<>();
            }
        }
    }

    public void hideGetEISFields(String requestor, RpaEntity.Type type, List<String> iccids) {
        hideGetEISFields(requestor, type);
        if (iccids != null && iccids.size() > 0) {
            // Only limit to those on our list
            List<ProfileInfo> pl = new ArrayList<>();
            for (ProfileInfo p : profiles)
                if (iccids.contains(p.iccid))
                    pl.add(p);
            profiles = pl;
        }
    }

    public static Eis fromModel(io.njiwa.sr.model.Eis mEis) throws Exception {
        Eis eis = new Eis();
        eis.signedInfo = Utils.XML.fromXML(mEis.getSignedInfoXML(), EumSignedInfo.class);
        eis.sig = Utils.XML.fromXML(mEis.getSignatureXML(), Signature.class);

        eis.remainingMemory = mEis.getRemainingMemory();
        eis.availableMemoryForProfiles = mEis.getAvailableMemoryForProfiles();
        try {
            GregorianCalendar c = new GregorianCalendar();
            c.setTime(mEis.getLastAuditDate());
            eis.lastAudit = DatatypeFactory.newInstance().newXMLGregorianCalendar(c).toString();
        } catch (Exception ex) {
        }
        eis.smsrId = mEis.getSmsr_id();

        // Do SMS-R SD
        try {
            List<io.njiwa.sr.model.SecurityDomain> sdlist = mEis.getSdList();
            io.njiwa.sr.model.SecurityDomain sd = null;
            for (io.njiwa.sr.model.SecurityDomain s : sdlist)
                if (s.getRole() == io.njiwa.sr.model.SecurityDomain.Role.ISDR) {
                    sd = s;
                    break;
                }
            eis.isdR = SecurityDomain.fromModel(sd);
        } catch (Exception ex) {
        }
        // Do Profiles
        eis.profiles = new ArrayList<>();
        try {

            for (io.njiwa.sr.model.ProfileInfo pp : mEis.getProfiles())
                eis.profiles.add(ProfileInfo.fromModel(pp));
        } catch (Exception ex) {
        }

        eis.properties = AdditionalProperties.fromModel(mEis.getProperties());
        eis.auditTrail = AuditTrail.fromModel(mEis.getAuditTrail());

        return eis;
    }

    public io.njiwa.sr.model.Eis toModel() throws Exception {
        // Make XML of signature and signed info
        String xmlSig = Utils.XML.toXML(sig);
        String xmlSignedInfo = Utils.XML.toXML(signedInfo);

        return toModel(xmlSignedInfo, xmlSig);
    }

    public io.njiwa.sr.model.Eis toModel(String xmlSignedInfo, String xmlSignature) throws Exception {
        List<io.njiwa.sr.model.SecurityDomain> securityDomainList = new ArrayList<>();
        io.njiwa.sr.model.SecurityDomain sd;
        // Put in the SDs
        try {
            sd = isdR.toModel();
            sd.setRole(io.njiwa.sr.model.SecurityDomain.Role.ISDR); // Force it to be an ISDR
            securityDomainList.add(sd);
        } catch (Exception ex) {
        }
        try {
            sd = signedInfo.ecasd.toModel();
            sd.setRole(io.njiwa.sr.model.SecurityDomain.Role.ECASD); // Force it to be an ECASD
            securityDomainList.add(sd);
        } catch (Exception ex) {
        }

        // String xmlSignedInfo = Utils.toXML(signedInfo);
        // String xmlSignature = Utils.toXML(sig);
        io.njiwa.sr.model.Eis eis = new io.njiwa.sr.model.Eis(signedInfo.eid,
                signedInfo.eumId,
                signedInfo.productionDate,
                signedInfo.platformType,
                signedInfo.platformVersion,
                (int) remainingMemory,
                (int) availableMemoryForProfiles,
                smsrId,
                signedInfo.isdPLoadFileAid,
                signedInfo.isdPModuleAid,
                signedInfo.euiCCCapabilities, xmlSignature, xmlSignedInfo,
                securityDomainList);

        // Do properties and audit trail
        eis.setProperties(properties != null ? properties.toModel() : null);
        auditTrail.toModel(eis);
        List<io.njiwa.sr.model.ProfileInfo> pl = new ArrayList<>();
        try {
            for (ProfileInfo pp : profiles)
                pl.add(pp.toModel(eis));
        } catch (Exception ex) {
        }
        eis.setProfiles(pl);
        return eis;
    }

    @XmlRootElement(namespace = "http://namespaces.gsma.org/esim-messaging/1")
    public static class EumSignedInfo implements RpsElement {

        @XmlElement(name = "Eid")
        public String eid;

        @XmlElement(name = "Eum-Id")
        public String eumId;

        @XmlElement(name = "ProductionDate")
        public String productionDate;

        @XmlElement(name = "PlatformType")
        public String platformType;

        @XmlElement(name = "PlatformVersion")
        public String platformVersion;

        @XmlElement(name = "Isd-p-loadfile-aid")
        public String isdPLoadFileAid;

        @XmlElement(name = "Isd-p-module-aid")
        public String isdPModuleAid;

        @XmlElement(name = "Ecasd")
        public SecurityDomain ecasd;

        @XmlElement(name = "EuiccCapabilities")
        public EuiCCCapabilities euiCCCapabilities;


    }

    @XmlRootElement(namespace = "http://namespaces.gsma.org/esim-messaging/1")
    public static class ProfileInfo implements RpsElement {
        @XmlElement(name = "Iccid")
        public String iccid;
        @XmlElement(name = "Isd-p-aid")
        public String isd_p_aid;
        @XmlElement(name = "Mno-id")
        public String mno_id;
        @XmlElement(name = "FallbackAttribute")
        public boolean fallback;
        @XmlElement(name = "SubscriptionAddress")
        public SubscriptionAddress subscriptionAddress;
        @XmlElement(name = "State")
        public io.njiwa.sr.model.ProfileInfo.State state;

        @XmlElement(name = "Smdp-id")
        public String smpd_id;
        @XmlElement(name = "ProfileType")
        public String profileType;
        @XmlElement(name = "AllocatedMemory")
        public int allocatedMemory;
        @XmlElement(name = "FreeMemoery")
        public int freeMemory;
        @XmlElement(name = "pol2")
        public Pol2Type pol2;

        public io.njiwa.sr.model.ProfileInfo toModel(io.njiwa.sr.model.Eis eis)
                throws Exception {
            io.njiwa.sr.model.ProfileInfo p = new io.njiwa.sr.model.ProfileInfo(eis,
                    iccid, mno_id, smpd_id, subscriptionAddress != null ? subscriptionAddress.msisdn : null,
                    subscriptionAddress != null ? subscriptionAddress.imsi : null,
                    state,
                    isd_p_aid, profileType, allocatedMemory, freeMemory,
                    null, fallback);
            if (pol2 != null)
                pol2.toModel(p);
            return p;
        }

        public static ProfileInfo fromModel(io.njiwa.sr.model.ProfileInfo p) {
            ProfileInfo px = new ProfileInfo();
            px.iccid = p.getIccid();
            px.isd_p_aid = p.getIsd_p_aid();
            px.mno_id = p.getMno_id();
            px.fallback = p.getFallbackAttr();
            px.subscriptionAddress = new SubscriptionAddress(p.getImsi(), p.getMsisdn());
            px.state = p.getState();
            px.smpd_id = p.getSmdpOID();
            px.profileType = p.getProfileType();
            px.allocatedMemory = p.getAllocatedMemory();
            px.freeMemory = p.getFreeMemory();
            px.pol2 = Pol2Type.fromModel(p);

            return px;
        }

        public void hideNotificationFields() {
            subscriptionAddress = null;
            fallback = false;
            state = null;
            allocatedMemory = 0;
            freeMemory = 0;
            pol2 = null;
        }
    }

    @XmlRootElement(namespace = "http://namespaces.gsma.org/esim-messaging/1")
    public static class AdditionalProperties {
        @XmlElement
        public List<Property> properties;

        public AdditionalProperties() {
        }

        public AdditionalProperties(List<Property> propertyList) {
            this.properties = propertyList;
        }

        public Map<String, String> toModel() {
            Map<String, String> map = new HashMap<>();
            try {
                for (Property p : properties)
                    map.put(p.key, p.value);
            } catch (Exception ex) {
            }
            return map;
        }

        public static AdditionalProperties fromModel(Map<String, String> map) {
            List<Property> pl = new ArrayList<>();
            try {
                for (Map.Entry<String, String> e : map.entrySet())
                    pl.add(new Property(e.getKey(), e.getValue()));
            } catch (Exception ex) {
            }

            return new AdditionalProperties(pl);
        }

        public static class Property {
            @XmlElement
            public String key;
            @XmlElement
            public String value;

            public Property() {
            }

            public Property(String key, String value) {
                this.key = key;
                this.value = value;
            }
        }
    }


    @XmlRootElement(namespace = "http://namespaces.gsma.org/esim-messaging/1")
    public static class AuditTrail {

        @XmlElement
        public List<AuditTrailRecord> auditTrailRecords;

        public void toModel(io.njiwa.sr.model.Eis eis) {
            List<io.njiwa.sr.model.AuditTrail> l = new ArrayList<>();
            try {
                for (AuditTrailRecord r : auditTrailRecords)
                    l.add(r.toModel(eis));
            } catch (Exception ex) {
            }
            eis.setAuditTrail(l);
        }

        public static AuditTrail fromModel(List<io.njiwa.sr.model.AuditTrail> l) {
            AuditTrail a = new AuditTrail();
            a.auditTrailRecords = new ArrayList<>();
            try {
                for (io.njiwa.sr.model.AuditTrail ax : l)
                    a.auditTrailRecords.add(AuditTrailRecord.fromModel(ax));
            } catch (Exception ex) {
            }
            return a;
        }

        @XmlRootElement(name = "AuditTrailRecordType", namespace = "http://namespaces.gsma.org/esim-messaging/1")
        public static class AuditTrailRecord {
            @XmlElement(name = "Eid")
            public String eid;
            @XmlElement(name = "Smsr-id")
            public String smsrId;
            @XmlElement(name = "OperationDate")
            public XMLGregorianCalendar operationDate;
            @XmlElement(name = "OperationType")
            public String operationType;
            @XmlElement(name = "RequesterId")
            public String requesterid;
            @XmlElement(name = "OperationExecutionStatus")
            public BaseResponseType.ExecutionStatus status;
            @XmlElement(name = "Isd-p-aid")
            public String isdpAid;
            @XmlElement(name = "Iccid")
            public String iccid;
            @XmlElement(name = "Imei")
            public String imei;
            @XmlElement(name = "Meid")
            public String meid;

            public io.njiwa.sr.model.AuditTrail toModel(io.njiwa.sr.model.Eis eis) throws Exception {


                return new io.njiwa.sr.model.AuditTrail(eis, eid, operationDate, operationType, requesterid,
                        status,
                        isdpAid, iccid, imei, meid, smsrId);
            }

            public static AuditTrailRecord fromModel(io.njiwa.sr.model.AuditTrail a) throws Exception {
                AuditTrailRecord ax = new AuditTrailRecord();
                ax.eid = a.getEid();
                ax.iccid = a.getIccid();
                ax.smsrId = a.getSmsrId();
                ax.operationDate = Utils.gregorianCalendarFromDate(a.getOperationDate());
                ax.operationType = a.getOperationType();
                ax.requesterid = a.getRequestorID();
                ax.status = new ObjectMapper().readValue(a.getStatus(), BaseResponseType.ExecutionStatus.class);
                ax.isdpAid = a.getIsdpAID();
                ax.imei = a.getImei();
                ax.meid = a.getMeid();
                return ax;
            }

            /**
             * @param operationType
             * @return
             * @brief Convert operation code (Sec 5.1.1.3.12 of SGP 02 v3.1) into operation name (e.g. CreateISDP)
             */
            public static String operationName(String operationType) {
                int code = 0;
                try {
                    code = Integer.parseInt(operationType, 16);
                } catch (Exception ex) {
                }
                switch (code) {
                    case 0x0100:
                        return "CreateISDP";
                    case 0x0200:
                        return "EnableProfile";
                    case 0x0300:
                        return "DisableProfile";
                    case 0x0400:
                        return "DeleteProfile";
                    case 0x0500:
                        return "eUICCCapabilityAudit";
                    case 0x0600:
                        return "MasterDelete";
                    case 0x0700:
                        return "SetFallbackAttribute";
                    case 0x0800:
                        return "EstablishISDRkeyset";
                    case 0x0900:
                        return "FinaliseISDRhandover";
                    default:
                        return operationType;
                }
            }
        }
    }

    @XmlRootElement(namespace = "http://namespaces.gsma.org/esim-messaging/1")
    public static class SecurityDomain {
        @XmlElement(name = "Aid")
        public String aid;
        @XmlElement(name = "Tar")
        public String tar;

        @XmlElement(name = "Sin")
        public String sin;
        @XmlElement(name = "Sdin")
        public String sdin;

        @XmlElement(name = "Role")
        public Role role;

        @XmlElement(name="Keyset")
        public List<KeySet> keySets;


        public SecurityDomain() {
        }

        public SecurityDomain(String aid, String tar, String sin, String sdin, Role role, List<KeySet> kl) {
            this.aid = aid;
            this.tar = tar;
            this.sin = sin;
            this.sdin = sdin;
            this.role = role;
            this.keySets = kl;
        }

        public static SecurityDomain fromModel(io.njiwa.sr.model.SecurityDomain sd) {
            List<KeySet> kl = new ArrayList<KeySet>();

            try {
                for (io.njiwa.common.model.KeySet k : sd.getKeysets())
                    kl.add(KeySet.fromModel(k));
            } catch (Exception ex) {
            }
            return new SecurityDomain(sd.getAid(),
                    sd.getTARs(),
                    sd.getSin(),
                    sd.getSdin(),
                    Role.fromModel(sd.getRole()),
                    kl);
        }

        public io.njiwa.sr.model.SecurityDomain toModel() {
            List<io.njiwa.common.model.KeySet> kl = new ArrayList<io.njiwa.common.model.KeySet>();
            try {
                for (KeySet k : keySets)
                    kl.add(k.toModel());
            } catch (Exception ex) {
            }
            return new io.njiwa.sr.model.SecurityDomain(aid, sin, sdin, role.toModel(), tar, kl);
        }

        @XmlEnum
        public enum Role {
            @XmlEnumValue("ISD-R")ISDR,
            @XmlEnumValue("ECASD")
            ECASD;

            public static Role fromModel(io.njiwa.sr.model.SecurityDomain.Role role) {
                switch (role) {
                    case ISDR:
                        return ISDR;
                    default:
                        return ECASD;
                }
            }

            public io.njiwa.sr.model.SecurityDomain.Role toModel() {
                switch (this) {
                    case ISDR:
                        return io.njiwa.sr.model.SecurityDomain.Role.ISDR;
                    default:
                        return io.njiwa.sr.model.SecurityDomain.Role.ECASD;
                }
            }
        }

        @XmlRootElement(namespace = "http://namespaces.gsma.org/esim-messaging/1")
        public static class KeySet {
            @XmlElement(name = "Version")
            public String version;
            @XmlElement(name = "Type")
            public Type type;

            @XmlElement(name = "Cntr")
            public long counter;

            @XmlElement(name="Key")
            public List<Key> keys;

            @XmlElement(name="Certificate")
            public List<Certificate> certificates;

            public KeySet() {
            }

            public KeySet(String version, Type type, List<Key> kl, List<Certificate> cl, long counter) {
                this.version = version;
                this.type = type;
                this.counter = counter;
                this.certificates = cl;
                this.keys = kl;
            }

            public static KeySet fromModel(io.njiwa.common.model.KeySet keySet) {
                List<Key> klist = new ArrayList<Key>();
                List<Certificate> clist = new ArrayList<Certificate>();
                try {
                    for (io.njiwa.common.model.Key k : keySet.getKeys())
                        klist.add(Key.fromModel(k));
                } catch (Exception ex) {
                }
                try {
                    for (io.njiwa.common.model.Certificate c : keySet.getCertificates())
                        clist.add(Certificate.fromModel(c));
                } catch (Exception ex) {
                }

                return new KeySet(keySet.getVersion().toString(), keySet.keysetType().toWsType(keySet.keysetType()),
                        klist, clist, keySet.getCounter());
            }

            public int versionAsInt() {
                try {
                    return Integer.parseInt(version, 16);
                } catch (Exception ex) {
                }
                return 0;
            }

            public io.njiwa.common.model.KeySet toModel() {
                List<io.njiwa.common.model.Certificate> cl = new ArrayList<io.njiwa.common.model.Certificate>();
                List<io.njiwa.common.model.Key> kl = new ArrayList<io.njiwa.common.model.Key>();
                try {
                    for (Certificate c : certificates)
                        cl.add(c.toModel());
                } catch (Exception ex) {
                }
                try {
                    for (Key k : keys)
                        kl.add(k.toModel());
                } catch (Exception ex) {
                }
                return new io.njiwa.common.model.KeySet(version, type, cl, kl, counter);
            }

            public enum Type {
                SCP03, SCP80, SCP81, TokenGeneration, ReceiptVerification, CA
            }

            @XmlRootElement(namespace = "http://namespaces.gsma.org/esim-messaging/1")
            public static class Key {
                @XmlAttribute(name = "kcv")
                public String keyCheckValue;

                @XmlElement(name = "Index")
                public long index;

                @XmlElement(name="KeyComponents")
                List<Component> components;

                public Key() {
                }

                public Key(long index, String keyCheckValue, List<Component> components) {
                    this.index = index;
                    this.keyCheckValue = keyCheckValue;
                    this.components = components;
                }

                public static Key fromModel(io.njiwa.common.model.Key key) {
                    List<Component> clist = new ArrayList<Component>();
                    try {
                        for (KeyComponent kc : key.getKeyComponents())
                            clist.add(new Component(kc.getType().toString(), kc.getValue()));
                    } catch (Exception ex) {
                    }
                    return new Key(key.getIndex(), key.getCheckValue(), clist);
                }

                io.njiwa.common.model.Key toModel() {
                    List<KeyComponent> clist = new ArrayList<KeyComponent>();
                    if (components != null)
                        for (Component c : components)
                            clist.add(new KeyComponent(c.value, KeyComponent.Type.fromString(c.type)));
                    return new io.njiwa.common.model.Key((int) index, keyCheckValue, clist);
                }

                @XmlRootElement(name = "KeyComponent")
                public static class Component {
                    @XmlAttribute
                    public String type; // hex-coded
                    @XmlAttribute
                    public String value;

                    public Component() {
                    }

                    public Component(String type, String value) {
                        this.type = type;
                        this.value = value;
                    }
                }
            }

            @XmlRootElement(namespace = "http://namespaces.gsma.org/esim-messaging/1")
            public static class Certificate {
                @XmlElement(name = "Index")
                public long index;
                @XmlElement(name = "CaId")
                public String caId;
                @XmlElement(name = "Value")
                public String value;

                public Certificate() {
                }

                public Certificate(long index, String caId, String value) {
                    this.index = index;
                    this.caId = caId;
                    this.value = value;
                }

                public static Certificate fromModel(io.njiwa.common.model.Certificate cert) {
                    return new Certificate(cert.getIndex(), cert.getCaId(), cert.getValue());
                }

                io.njiwa.common.model.Certificate toModel() {
                    return new io.njiwa.common.model.Certificate(value, caId, (int) index);
                }
            }

        }
    }

    @XmlRootElement(namespace = "http://namespaces.gsma.org/esim-messaging/1")
    public static class EuiCCCapabilities implements RpsElement {
        @XmlElement(name = "CattpSupport")
        public boolean cattpSupport;
        @XmlElement(name = "CattpVersion")
        public String cattpVersion;
        @XmlElement(name = "HttpSupport")
        public boolean httpSupport;
        @XmlElement(name = "HttpVersion")
        public String httpVersion;
        @XmlElement(name = "SecurePacketVersion")
        public String securePacketVersion;
        @XmlElement(name = "RemoteProvisioningVersion")
        public String remoteProvisioningVersion;
    }
}
