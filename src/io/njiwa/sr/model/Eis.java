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

package io.njiwa.sr.model;

import io.njiwa.common.PersistenceUtility;
import io.njiwa.common.Utils;
import io.njiwa.common.model.Certificate;
import io.njiwa.common.model.KeySet;
import io.njiwa.common.model.TransactionType;
import io.njiwa.common.ServerSettings;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;

import javax.persistence.*;
import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;
import java.util.*;

/**
 * Created by bagyenda on 20/04/2016.
 */
@Entity
@Table(name = "eis_entries",
        uniqueConstraints = {
                @UniqueConstraint(columnNames = {"eid"}, name = "eis_key_ct")
        }, indexes = {
        @Index(columnList = "eid", name = "eis_idx1"),
        @Index(columnList = "eum_id", name = "eis_idx2"),
}
)
@SequenceGenerator(name = "eis", sequenceName = "eis_seq")
@DynamicUpdate
@DynamicInsert
public class Eis {

    public final static String ISDP_LOAD_FILE_AID = "A0000005591010FFFFFFFF8900000D00";
    public final static String ISDP_EXEC_MODULE_AID = "A0000005591010FFFFFFFF890000E00";

    @Id
    @Column(name = "id", unique = true, nullable = false, updatable = false)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "eis")
    private
    Long Id;

    @Column(nullable = false, name = "date_added", columnDefinition = "timestamp default current_timestamp", updatable = false, insertable = false)
    private
    Date dateAdded;

    @Column(name = "eid", nullable = false, columnDefinition = "text")
    private
    String eid; // The actual EID

    @Column(name = "eum_id", nullable = false, columnDefinition = "text")
    private
    String eumId;

    @OneToMany(mappedBy = "eis", cascade = CascadeType.ALL,orphanRemoval = true)
    private
    List<ProfileInfo> profiles;

    @OneToMany(mappedBy = "eis", cascade = CascadeType.ALL,orphanRemoval = true)
    private
    List<AuditTrail> auditTrail;

    @Column(nullable = false)
    private
    Date productionDate;

    @Column(nullable = false, columnDefinition = "text")
    private
    String platformType;

    @Column(nullable = false, columnDefinition = "text")
    private
    String platformVersion;

    @Column(nullable = false)
    private
    Integer remainingMemory;
    @Column(nullable = false)
    private
    Integer availableMemoryForProfiles;

    @Column(nullable = true)
    private
    Date lastAuditDate;

    @Column(nullable = false, columnDefinition = "text")
    private
    String smsr_id;

    @Column(columnDefinition = "text")
    private String oldSmsRId;

    @Column(nullable = false, columnDefinition = "text")
    private
    String isd_p_loadfile_aid;
    @Column(nullable = false, columnDefinition = "text")
    private String isd_p_module_aid;


    @OneToMany(mappedBy = "eis", orphanRemoval = true, cascade = CascadeType.ALL)
    private
    List<SecurityDomain> sdList; // Including ISD-R and EACSD

    // eUICC capabilities fields
    @Column(nullable = false)
    private
    Boolean cat_tp_support;
    @Column(nullable = true)
    private
    String cat_tp_version;
    @Column(nullable = false)
    private
    Boolean http_support;
    @Column(nullable = true)
    private
    String http_version;
    @Column(nullable = true)
    private
    String secure_packet_version;
    @Column(nullable = true)
    private
    String remote_provisioning_version;


    @Column(nullable = false, columnDefinition = "text")
    private
    String signatureXML; // Contains entire XML signature

    @Column(nullable = false, columnDefinition = "text")
    private
    String signedInfoXML; // Contains XML of signedInfo.

    // Book-keeping stuff for BIP
    @Column(name = "numBipOpenRequests", nullable = false, columnDefinition = "int not null default 0", insertable = false)
    private
    Integer numPendingBipRequests = 0; //!< Counter of the number of BIP OPEN/PUSH commands pending
    @Column(name = "last_bip_request", nullable = true)
    private
    Date lastBipRequest; //!< Last BIP request date/time
    @Column(name = "last_bip_connect", nullable = true)
    private Date lastBipConnect; //!< When was the last BIP connection?
    @Column(name = "has_data_plan", nullable = false, columnDefinition = "boolean NOT NULL DEFAULT false")
    private Boolean hasDataPlan = false; //!< Does this have a data plan?
    @Column(name = "last_data_plan_fetch")
    private Date lastDataPlanFetch; //!< When was data plan last fetched?

    @Column(name = "last_ram_push_request", nullable = true)
    private
    Date lastRAMPushRequest; //!< Last SCWS Push request date/time

    @Column(name = "last_ram_http_request")
    private Date lastRAMHttpRequest;

    @Column(name = "num_pending_ram_requests", nullable = false)
    private Integer numPendingRAMRequests = 0;

    @Column(nullable = false, columnDefinition = "int not null default 0", insertable = false)
    private
    Integer lastNotificationSequenceNumber;

    @Column()
    private
    String imei; // The device IMEI when received.

    @Column
    private
    String meid; // According to 3GPP2 C.S0035-B

    @Column(nullable = false, columnDefinition = "boolean not null default false")
    private
    Boolean registrationComplete;

    /**
     * @brief The current, pending profile change. Only one profile change can be pending at a time.
     */
    @Column(insertable = false)
    private
    Long pendingProfileChangeTransaction;

    @Column(insertable = false,  columnDefinition = "boolean not null default false")
    private Boolean scriptChainingActive; // Whether ETSI TS 102 226 script chaining is active or not.

    @Column(insertable = false)
    private Long pendingEuiccHandoverTransaction;
    @ElementCollection
    @CollectionTable(name = "sr_eis_allowed_management_mnos")
    @Column(name = "allowed_mno")
    private Set<String> allowedManagementMNOs;
    @ElementCollection
    @CollectionTable(name = "sr_eis_denied_management_mnos")
    @Column(name = "denied_mno")
    private Set<String> deniedManagementMNOs;
    @ElementCollection
    @CollectionTable(name = "sr_eis_properties")
    @MapKeyColumn(name = "key", columnDefinition = "TEXT")
    @Column(name = "propert_value", columnDefinition = "TEXT")
    private Map<String, String> properties;
    @Transient
    private Eid eidObj;
    @Transient
    private SecurityDomain isdr = null;
    @Column
    private
    Date lastNetworkAttach;

    public Eis() {
    }

    public Eis(String eid, String eumId, Object productionDate, String platformType, String platformVersion,
               int remainingMemory, int availableMemoryForProfiles, String smsr_id,
               String isd_p_loadfile_aid, String isd_p_module_aid, io.njiwa.sr.ws.types.Eis
                       .EuiCCCapabilities caps,
               String signatureXML, String signedInfoXML,
               List<SecurityDomain> sdList) throws Exception {
        setEid(eid);
        setEumId(eumId);
        Date pDate = null;
        if (productionDate instanceof Date)
            pDate = (Date) productionDate;
        else if (productionDate instanceof String)
            try {
                pDate = DatatypeConverter.parseDateTime((String) productionDate).getTime();
            } catch (Exception ex) {
            }

        setProductionDate(pDate);
        setPlatformType(platformType);
        setPlatformVersion(platformVersion);
        setRemainingMemory(remainingMemory);
        setAvailableMemoryForProfiles(availableMemoryForProfiles);
        setSmsr_id(smsr_id);
        setIsd_p_loadfile_aid(isd_p_loadfile_aid);
        setIsd_p_module_aid(isd_p_module_aid);
        setCat_tp_support(caps.cattpSupport);
        setCat_tp_version(caps.cattpVersion);
        setHttp_support(caps.httpSupport);
        setHttp_version(caps.httpVersion);
        setSecure_packet_version(caps.securePacketVersion);
        setRemote_provisioning_version(caps.remoteProvisioningVersion);
        setSignatureXML(signatureXML);
        setSignedInfoXML(signedInfoXML);
        setRegistrationComplete(true);
        try {
            for (SecurityDomain s : sdList)
                s.setEis(this);
        } catch (Exception ex) {
        }
        setSdList(sdList);

        eidObj = new Eid(getEid()); // Validate it
    }

    public static Eis findByEid(EntityManager em, byte eid[]) {
        return findByEid(em, Utils.HEX.b2h(eid));
    }

    public static Eis findByEid(EntityManager em, String eid) {

        try {
            return em.createQuery("from Eis WHERE eid = :eid", Eis.class)
                    .setParameter("eid", eid)
                    .setMaxResults(1)
                    .getSingleResult();
        } catch (Exception ex) {
            String xs = ex.getMessage();
        }
        return null;
    }

    public static Eis findByEid(PersistenceUtility po, final String eid) {
        return po.doTransaction((po1, em) -> findByEid(em, eid));
    }

    public static Eis findByMsisdn(EntityManager em, String msisdn) {
        ProfileInfo p = ProfileInfo.fromMsisdn(em, msisdn);
        return p != null ? p.getEis() : null;
    }

    public static Eis deleteProfiles(EntityManager em, long eid, List<String> aids) {
        Eis eis = null;
        try {
            eis = em.find(Eis.class, eid, LockModeType.PESSIMISTIC_WRITE);
            for (String aid : aids) {
                ProfileInfo p = eis.findProfileByAID(aid);
                if (p != null) {
                    p.setState(ProfileInfo.State.Deleted);
                    em.remove(p); // Deleted
                } else
                    Utils.lg.severe(String.format("Failed to find profile with AID [%s] on euicc [%s] will deleting " +
                                    "ISD-P records",
                            aid, eis));
            }
        } catch (Exception ex) {

        }
        return eis;
    }

    public boolean managementAllowed(String mnoId) {
        try {
            Set<String> l = getDeniedManagementMNOs();
            if (l.contains(mnoId))
                return false;
        } catch (Exception ex) {
        }

        try {
            Set<String> l = getAllowedManagementMNOs();
            if (l == null || l.size() == 0)
                return true; // All are allowed
            return l.contains(mnoId);
        } catch (Exception ex) {
            return false;
        }
    }

    public boolean verifyPendingEuiCCHandoverTransaction(PersistenceUtility po) {
        return po.doTransaction(new PersistenceUtility.Runner<Boolean>() {
            @Override
            public Boolean run(PersistenceUtility po, EntityManager em) throws Exception {
                return verifyPendingEuiCCHandoverTransaction(em);
            }

            @Override
            public void cleanup(boolean success) {

            }
        });
    }

    public boolean verifyPendingEuiCCHandoverTransaction(EntityManager em) {
        try {
            long trId = getPendingEuiccHandoverTransaction();
            SmSrTransaction.Status status = em.createQuery("select status from SmSrTransaction where id = :i", SmSrTransaction.Status.class)
                    .setParameter("i", trId)
                    .setMaxResults(1)
                    .getSingleResult();
            if (status == SmSrTransaction.Status.Completed || status == SmSrTransaction.Status.Failed || status ==
                    SmSrTransaction.Status.Expired) {
                setPendingEuiccHandoverTransaction(null);
                return false;
            }
            return true;
        } catch (Exception ex) {
            setPendingEuiccHandoverTransaction(null);
        }
        return false;
    }


    public boolean hasHttpSupport() {
        if (getHttp_support() == false)
            return false;
        // Now find suitable keyset
        try {
            boolean hasKeys = false;
            List<KeySet> kl = findISDR().getKeysets();
            for (KeySet k : kl)
                if (k.getType() == KeySet.Type.SCP81) {
                    hasKeys = true;
                    break;
                }
            return hasKeys;
        } catch (Exception ex) {
        }
        return false;
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

    public String getEid() {
        return eid;
    }

    public void setEid(String eid) {
        this.eid = eid;
    }

    public String getEumId() {
        return eumId;
    }

    public void setEumId(String eum_id) {
        this.eumId = eum_id;
    }

    public List<ProfileInfo> getProfiles() {
        return profiles;
    }

    public void setProfiles(List<ProfileInfo> profiles) {
        this.profiles = profiles;
    }

    public Date getProductionDate() {
        return productionDate;
    }

    public void setProductionDate(Date productionDate) {
        this.productionDate = productionDate;
    }

    public String getPlatformType() {
        return platformType;
    }

    public void setPlatformType(String platformType) {
        this.platformType = platformType;
    }

    public String getPlatformVersion() {
        return platformVersion;
    }

    public void setPlatformVersion(String platformVersion) {
        this.platformVersion = platformVersion;
    }

    public Integer getRemainingMemory() {
        return remainingMemory;
    }

    public void setRemainingMemory(Integer remainingMemory) {
        this.remainingMemory = remainingMemory;
    }

    public Integer getAvailableMemoryForProfiles() {
        return availableMemoryForProfiles;
    }

    public void setAvailableMemoryForProfiles(Integer availableMemoryForProfiles) {
        this.availableMemoryForProfiles = availableMemoryForProfiles;
    }

    public void addToAuditTrail(EntityManager em, AuditTrail a) {
        a.setEis(this);
        a.setEid(getEid());

        List<AuditTrail> l = getAuditTrail();
        if (l == null)
            l = new ArrayList<>();
        l.add(a);
        em.persist(a);
    }

    public Date getLastAuditDate() {
        return lastAuditDate;
    }

    public void setLastAuditDate(Date lastAuditDate) {
        this.lastAuditDate = lastAuditDate;
    }

    public String getSmsr_id() {
        return smsr_id;
    }

    public void setSmsr_id(String smsr_id) {
        this.smsr_id = smsr_id;
    }

    public String getIsd_p_loadfile_aid() {
        return isd_p_loadfile_aid;
    }

    public void setIsd_p_loadfile_aid(String isd_p_loadfile_aid) {
        this.isd_p_loadfile_aid = isd_p_loadfile_aid;
    }

    public String getIsd_p_module_aid() {
        return isd_p_module_aid;
    }

    public void setIsd_p_module_aid(String isd_p_module_aid) {
        this.isd_p_module_aid = isd_p_module_aid;
    }

    public List<SecurityDomain> getSdList() {
        return sdList;
    }

    public void setSdList(List<SecurityDomain> sdList) {
        this.sdList = sdList;
    }

    public Boolean getCat_tp_support() {
        return cat_tp_support;
    }

    public void setCat_tp_support(Boolean cat_tp_support) {
        this.cat_tp_support = cat_tp_support;
    }

    public String getCat_tp_version() {
        return cat_tp_version;
    }

    public void setCat_tp_version(String cat_tp_version) {
        this.cat_tp_version = cat_tp_version;
    }

    public Boolean getHttp_support() {
        return http_support;
    }

    public void setHttp_support(Boolean http_support) {
        this.http_support = http_support;
    }

    public String getHttp_version() {
        return http_version;
    }

    public void setHttp_version(String http_version) {
        this.http_version = http_version;
    }

    public String getSecure_packet_version() {
        return secure_packet_version;
    }

    public void setSecure_packet_version(String secure_packet_version) {
        this.secure_packet_version = secure_packet_version;
    }

    public String getRemote_provisioning_version() {
        return remote_provisioning_version;
    }

    public void setRemote_provisioning_version(String remote_provisioning_version) {
        this.remote_provisioning_version = remote_provisioning_version;
    }

    public String getSignatureXML() {
        return signatureXML;
    }

    public void setSignatureXML(String signature) {
        this.signatureXML = signature;
    }

    public String getSignedInfoXML() {
        return signedInfoXML;
    }

    public void setSignedInfoXML(String signedInfoXML) {
        this.signedInfoXML = signedInfoXML;
    }

    public String activeMISDN() {
        try {
            for (ProfileInfo p : getProfiles())
                if (p.getState() == ProfileInfo.State.Enabled)
                    return p.getMsisdn();
        } catch (Exception ex) {
        }
        return null;
    }

    public Integer getNumPendingBipRequests() {
        return numPendingBipRequests;
    }

    public void setNumPendingBipRequests(Integer numPendingBipRequests) {
        this.numPendingBipRequests = numPendingBipRequests;
    }

    public Date getLastBipRequest() {
        return lastBipRequest;
    }

    public void setLastBipRequest(Date lastBipRequest) {
        this.lastBipRequest = lastBipRequest;
    }

    public Date getLastBipConnect() {
        return lastBipConnect;
    }

    public void setLastBipConnect(Date lastBipConnect) {
        this.lastBipConnect = lastBipConnect;
    }

    public Boolean getHasDataPlan() {
        return hasDataPlan;
    }

    public void setHasDataPlan(Boolean hasDataPlan) {
        this.hasDataPlan = hasDataPlan;
    }

    public Date getLastDataPlanFetch() {
        return lastDataPlanFetch;
    }

    public void setLastDataPlanFetch(Date lastDataPlanFetch) {
        this.lastDataPlanFetch = lastDataPlanFetch;
    }

    public Date getLastRAMPushRequest() {
        return lastRAMPushRequest;
    }

    public void setLastRAMPushRequest(Date lastRAMPushRequest) {
        this.lastRAMPushRequest = lastRAMPushRequest;
    }

    public Date getLastRAMHttpRequest() {
        return lastRAMHttpRequest;
    }

    public void setLastRAMHttpRequest(Date lastRAMHttpRequest) {
        this.lastRAMHttpRequest = lastRAMHttpRequest;
    }

    public Integer getNumPendingRAMRequests() {
        return numPendingRAMRequests;
    }

    public void setNumPendingRAMRequests(Integer numPendingRAMRequests) {
        this.numPendingRAMRequests = numPendingRAMRequests;
    }

    public SecurityDomain findSecurityDomainByAID(String aid) {
        try {
            for (SecurityDomain sd : getSdList())
                if (sd.getAid().equalsIgnoreCase(aid))
                    return sd;
        } catch (Exception ex) {

        }
        return null;
    }

    public ProfileInfo findProfileByAID(String aid) {
        try {
            for (ProfileInfo p : getProfiles())
                if (p.getIsd_p_aid().equalsIgnoreCase(aid))
                    return p;
        } catch (Exception ex) {

        }
        return null;
    }

    public ProfileInfo findProfileByICCID(String iccid) {
        try {
            for (ProfileInfo p : getProfiles())
                if (p.getIccid().equalsIgnoreCase(iccid))
                    return p;
        } catch (Exception ex) {

        }
        return null;
    }

    public ProfileInfo findEnabledProfile() {
        try {
            for (ProfileInfo p : getProfiles())
                if (p.getState() == ProfileInfo.State.Enabled)
                    return p;
        } catch (Exception ex) {

        }
        return null;
    }

    public ProfileInfo findFallBackProfile() {
        try {
            for (ProfileInfo p : getProfiles())
                if (p.getFallbackAttr())
                    return p;
        } catch (Exception ex) {

        }
        return null;
    }

    public synchronized SecurityDomain findISDR() {
        if (isdr == null)
            try {
                isdr = findSecurityDomain(SecurityDomain.Role.ISDR);
            } catch (Exception ex) {

            }
        return isdr;
    }

    public synchronized SecurityDomain findSecurityDomain(SecurityDomain.Role role) {
        try {
            for (SecurityDomain s : getSdList())
                if (s.getRole() == role)
                    return s;
        } catch (Exception ex) {
        }
        return null;
    }

    public Certificate.Data ecasdKeyAgreementCertificate() {
        SecurityDomain ecasd = findSecurityDomain(SecurityDomain.Role.ECASD);
        try {
            for (KeySet ks : ecasd.getKeysets())
                if (ks.getType() == KeySet.Type.CA)
                    try {
                        for (Certificate c : ks.getCertificates()) {
                            Certificate.Data d = Certificate.Data.decode(c.getValue());
                            if (d.keyUsage == Certificate.Data.KEYAGREEMENT)
                                return d;
                        }
                    } catch (Exception ex) {
                    }


        } catch (Exception ex) {

        }
        return null;
    }

    public String ISDPLOADFILEAID() {
        String loadAID = getIsd_p_loadfile_aid();
        if (loadAID == null)
            loadAID = ISDP_LOAD_FILE_AID;
        return loadAID;
    }

    public String ISDPMODULEAID() {
        String aid = getIsd_p_module_aid();
        if (aid == null)
            aid = ISDP_LOAD_FILE_AID;
        return aid;
    }

    /**
     * @return
     * @brief makes a new profile in installInProgress State, allocates it an AID, returns it
     */
    public synchronized ProfileInfo addNewProfile(String iccid, String mnoID, int allocMem, String smdpID) throws
            Exception {
        // Per appendix H of SGP doc, TAR range for ISDP is 00 00 10 - 00 FF FF
        long i;
        String tar = "";
        for (i = 0x000020; i <= 0x00FFFF; i++) {
            tar = String.format("%06X", i);
            if (ProfileInfo.findProfileByTAR(this, tar, false) == null)
                break;
        }

        if (i >= 0xFFFF)
            throw new Exception("Too many profiles in EIS entry");
        String loadAID = ISDPLOADFILEAID();

        // Get RID
        String rid = Utils.ridFromAID(loadAID);
        // Make PIX from TAR according to Annex H of SGP.02 v4.2
        String aid = rid + "1010" + "FFFF" + "FFFF89" + tar + "00";

        ProfileInfo p = new ProfileInfo(this,iccid,mnoID,smdpID,null,null,
                ProfileInfo.State.InstallInProgress,aid,null,allocMem,0,
                new ArrayList<>(),false);

        List<ProfileInfo> plist = getProfiles();
        if (plist == null)
            plist = new ArrayList<>();
        plist.add(p);
        return p;
    }

    public Integer getLastNotificationSequenceNumber() {
        return lastNotificationSequenceNumber;
    }

    public void setLastNotificationSequenceNumber(Integer lastNotificationSequenceNumber) {
        this.lastNotificationSequenceNumber = lastNotificationSequenceNumber;
    }

    public String getImei() {
        return imei;
    }

    public void setImei(String imei) {
        this.imei = imei;
    }

    public String getMeid() {
        return meid;
    }

    public void setMeid(String meid) {
        this.meid = meid;
    }

    public Long getPendingProfileChangeTransaction() {
        return pendingProfileChangeTransaction;
    }

    public void setPendingProfileChangeTransaction(Long pendingProfileChangeTransaction) {
        this.pendingProfileChangeTransaction = pendingProfileChangeTransaction;
    }

    public boolean verifyPendingProfileChangeTransaction(EntityManager em) {
        try {
            long tr = getPendingProfileChangeTransaction();
            SmSrTransaction.Status status = em.createQuery("select status from SmSrTransaction where id = :i",
                    SmSrTransaction.Status.class)
                    .setParameter("i", tr)
                    .setMaxResults(1)
                    .getSingleResult();
            if (status == SmSrTransaction.Status.Completed || status == SmSrTransaction.Status.Error
                    || status == SmSrTransaction.Status.Failed ||
                    status == SmSrTransaction.Status.Expired) {
                setPendingProfileChangeTransaction(null);
                return false;
            }
            return true; // There is one waiting...
        } catch (Exception ex) {
            return false;
        }
    }

    @Override
    public String toString() {
        String res = "", sep = "";
        try {
            res += "EID: " + getEid() + "";
            sep = ",";
            String msisdn = activeMISDN();
            if (msisdn != null)
                res += sep + "MSISDN: " + msisdn;
        } catch (Exception ex) {
        }
        return res;
    }

    public SmSrTransaction processNotification(NotificationMessage msg, EntityManager em) {
        // Handle it
        try {
            if (getLastNotificationSequenceNumber() == null ||
                    getLastNotificationSequenceNumber() < msg.sequenceNumber)
                setLastNotificationSequenceNumber(msg.sequenceNumber);
            else {
                Utils.lg.info(String.format("Received duplicate notification from [%s]" +
                        " (ours was [%d])" +
                        " ", msg, msg.sequenceNumber));
                return null;
            }
            if (msg.notificationType == NotificationMessage.Type.eUICCDeclaration) {
                if (msg.meid != null)
                    setMeid(msg.meid);
                if (msg.imei != null)
                    setImei(msg.imei);
                setLastNetworkAttach(Calendar.getInstance().getTime());
                // XXX Should we update the current profile based on received AID?
            } else {
                // Look for pending, etc.
                Long profileTrans = getPendingProfileChangeTransaction();
                SmSrTransaction t = em.find(SmSrTransaction.class, profileTrans, LockModeType
                        .PESSIMISTIC_WRITE);
                TransactionType transactionType = t.getTransObject();
                ProfileInfo.HandleNotification handleNotification = (ProfileInfo.HandleNotification) transactionType;
                handleNotification.processNotification(msg, em); // Process it.
                // Now make a new transaction, which will send a message to the eUICC confirming that we received the
                // notification
                Long cT = getPendingProfileChangeTransaction();
                Long requestingEntity = transactionType.requestingEntityId;
                NotificationMessage.HandleNotificationConfirmationTransaction obj = new NotificationMessage
                        .HandleNotificationConfirmationTransaction(cT, msg.sequenceNumber, requestingEntity);
                t = new SmSrTransaction(em, "NotificationConfirmation", "", null, this.getEid(), ServerSettings.Constants
                        .DEFAULT_VALIDITY, false, obj);
                em.persist(t); // Send it to DB
                return t;
            }
        } catch (Exception ex) {
            Utils.lg.severe(String.format("Failed to process notification: %s", ex));
            return null;
        }
        return null;
    }

    public Date getLastNetworkAttach() {
        return lastNetworkAttach;
    }

    public void setLastNetworkAttach(Date lastNetworkAttach) {
        this.lastNetworkAttach = lastNetworkAttach;
    }

    public Set<String> getAllowedManagementMNOs() {
        return allowedManagementMNOs;
    }

    public void setAllowedManagementMNOs(Set<String> allowedManagementMNOs) {
        this.allowedManagementMNOs = allowedManagementMNOs;
    }

    public Set<String> getDeniedManagementMNOs() {
        return deniedManagementMNOs;
    }

    public void setDeniedManagementMNOs(Set<String> deniedManagementMNOs) {
        this.deniedManagementMNOs = deniedManagementMNOs;
    }

    public Boolean getRegistrationComplete() {
        return registrationComplete;
    }

    public void setRegistrationComplete(Boolean registrationComplete) {
        this.registrationComplete = registrationComplete;
    }

    public String getOldSmsRId() {
        return oldSmsRId;
    }

    public void setOldSmsRId(String oldSmsRId) {
        this.oldSmsRId = oldSmsRId;
    }

    public Map<String, String> getProperties() {
        return properties;
    }

    public void setProperties(Map<String, String> properties) {
        this.properties = properties;
    }

    public List<AuditTrail> getAuditTrail() {
        return auditTrail;
    }

    public void setAuditTrail(List<AuditTrail> auditTrail) {
        this.auditTrail = auditTrail;
    }

    /**
     * @brief when this is set, no other transactions allowed until it is over.
     */
    public Long getPendingEuiccHandoverTransaction() {
        return pendingEuiccHandoverTransaction;
    }

    public void setPendingEuiccHandoverTransaction(Long pendingEuiccHandoverTransaction) {
        this.pendingEuiccHandoverTransaction = pendingEuiccHandoverTransaction;
    }

    public Boolean getScriptChainingActive() {
        return scriptChainingActive;
    }

    public void setScriptChainingActive(Boolean scriptChainingActive) {
        this.scriptChainingActive = scriptChainingActive;
    }

    // Represents a broken down EID from a string
    public static class Eid {
        // Represents an EID. And validates it
        public String countryCode; // As extracted from the EID
        public String issueId; // EUM ID
        public String versionInfo; // As extracted from...
        public String issuerInfo;
        public String issuerIID;
        public String fullEid;

        public Eid(String eid) throws Exception {
            // Verify it
            try {
                eid = eid.replaceAll("\\s+", "");
            } catch (Exception ex) {
                throw new Exception("Invalid EID");
            }
            if (eid.length() != 32)
                throw new Exception("Invalid EID length: Must be 32 ");
            if (eid.charAt(0) != '8' || eid.charAt(1) != '9')
                throw new Exception("Invalid EID: Must begin with '89'");
            try {
                countryCode = eid.substring(2, 5);
            } catch (Exception ex) {
                throw new Exception("Invalid EID: Must have 3-digit country code");
            }
            try {
                issueId = eid.substring(5, 8);
            } catch (Exception ex) {
                throw new Exception("Invalid EID: Must have 3-digit issuer ID");
            }

            try {
                String xs = eid.substring(8, 18);
                versionInfo = xs.substring(0, 5);
                issuerInfo = xs.substring(4);
            } catch (Exception ex) {
                throw new Exception("Invalid EID: Must have issuer-specific info");
            }

            try {
                issuerIID = eid.substring(18, 30);
            } catch (Exception ex) {
                throw new Exception("Invalid EID: Must have issue individual ID info");
            }


            // Now validate it

            BigInteger b;
            try {
                b = new BigInteger(eid);
            } catch (Exception ex) {
                throw new Exception("Invalid EID: Must be sequence of digits");
            }
            // Try for remainder and so forth: According to Annex J of SGP 02 v3.0
            int xrem;
            try {
                BigInteger rem = b.divideAndRemainder(new BigInteger("97"))[1];
                xrem = rem.intValue();
            } catch (Exception ex) {
                throw new Exception("Invalid EID: Fails checksum test");
            }
            if (xrem != 1)
                throw new Exception("Invalid checksum");

            fullEid = eid;
        }

    }
}
