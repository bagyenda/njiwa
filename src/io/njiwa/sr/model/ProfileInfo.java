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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.njiwa.common.Utils;
import io.njiwa.common.model.TransactionType;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;

import javax.persistence.*;
import java.util.Date;
import java.util.List;

/**
 * Created by bagyenda on 20/04/2016.
 * Profiles (i.e. SD-Ps)
 */
@Entity
@Table(name = "sr_profiles",
        uniqueConstraints = {
                @UniqueConstraint(columnNames = {"eis_id", "iccid"}, name = "prof_eis_ct"),
                @UniqueConstraint(columnNames = {"msisdn", "state"}, name = "prof_state_ct") // Can't have two active
                // with same MSISDN. Right? What about two disabled??
        }, indexes = {
        @Index(columnList = "msisdn,state", name = "prof_idx1"),

}
)
@SequenceGenerator(name = "profileinfo", sequenceName = "profileinfo_seq", allocationSize = 1)
@JsonIgnoreProperties(value = {"hibernateLazyInitializer", "eis"})
@DynamicUpdate
@DynamicInsert
public class ProfileInfo {
    @Id
    @Column(name = "id", unique = true, nullable = false, updatable = false)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "profileinfo")
    private
    Long Id;

    @Column(nullable = false, name = "date_added", columnDefinition = "timestamp default current_timestamp", updatable = false, insertable = false)
    private
    Date dateAdded;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    private Eis eis;

    @Column(nullable = false, columnDefinition = "text")
    private
    String iccid;

    @Column(nullable = false, columnDefinition = "text")
    private
    String isd_p_aid;


    @Column(nullable = false, columnDefinition = "text")
    private
    String mno_id;

    @Column(nullable = false)
    private
    Boolean fallbackAttr;

    // Subscription address: msisdn and imsi

    @Column(name = "msisdn", nullable = true)
    private
    String msisdn;

    @Column(name = "imsi", columnDefinition = "text")
    private
    String imsi;

    @Column(name = "state")
    @Enumerated(EnumType.STRING)
    private State state;

    @Column(nullable = true, columnDefinition = "text", name = "smdpOID")
    private // Can be null until set
            String smdpOID;

    @Column(columnDefinition = "text")
    private
    String profileType;

    @Column(nullable = false)
    private
    Integer allocatedMemory;

    @Column(nullable = true)
    private
    Integer freeMemory;
    @OneToMany(mappedBy = "profile", cascade = CascadeType.ALL, orphanRemoval = true)
    private
    List<Pol2Rule> pol2; // List of Profile rules

    public ProfileInfo() {
    }

    public ProfileInfo(Eis eis, String iccid, String mno_id, String smdpOID, String msisdn, String imsi, State state,
                       String isd_p_aid, String profileType, int allocatedMemory, int freeMemory,
                       List<Pol2Rule> pol, boolean fallbackAttr) {
        setEis(eis);
        setIccid(iccid);
        setState(state);
        setMno_id(mno_id);
        setSmdpOID(smdpOID);
        setMsisdn(msisdn);
        setImsi(imsi);
        setAllocatedMemory(allocatedMemory);
        setProfileType(profileType);
        setFreeMemory(freeMemory);
        setIsd_p_aid(isd_p_aid);
        setFallbackAttr(fallbackAttr);
        try {
            setPol2(pol);
            for (Pol2Rule p : pol)
                p.setProfile(this); // Mark back
        } catch (Exception ex) {
        }
    }

    public static ProfileInfo fromMsisdn(EntityManager em, String msisdn) {
        return em.createQuery("from ProfileInfo where msisdn = :m AND state = :s", ProfileInfo.class)
                .setParameter("m", msisdn)
                .setParameter("s", State.Enabled)
                .getSingleResult();
    }

    public static ProfileInfo findProfileByTAR(Eis eis, byte[] tar, boolean requireActive) {
        try {
            String xtar = Utils.HEX.b2H(tar);
            return findProfileByTAR(eis, xtar, requireActive);
        } catch (Exception ex) {
        }

        return null;
    }

    public static ProfileInfo findProfileByTAR(Eis eis, String tar, boolean requireActive) {
        try {

            for (ProfileInfo p : eis.getProfiles())
                if (p.TAR().equalsIgnoreCase(tar))
                    if (!requireActive ||
                            p.getState() == State.Created || p.getState() == State.Enabled) // Only send
                        // to those
                        // that
                        // are enabled
                        return p;
        } catch (Exception ex) {

        }
        return null;


    }

    public static void clearProfileChangFlag(EntityManager em, long tid, Eis eis) {
        if (eis != null && eis.getPendingProfileChangeTransaction() != null &&
                eis.getPendingProfileChangeTransaction() == tid)
            eis.setPendingProfileChangeTransaction(null);
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

    public Eis getEis() {
        return eis;
    }

    public void setEis(Eis eis) {
        this.eis = eis;
    }

    public String getIccid() {
        return iccid;
    }

    public void setIccid(String iccid) {
        this.iccid = iccid;
    }

    public String getIsd_p_aid() {
        return isd_p_aid;
    }

    public void setIsd_p_aid(String isp_p_aid) {
        this.isd_p_aid = isp_p_aid;
    }

    public String getMno_id() {
        return mno_id;
    }

    public void setMno_id(String mno_id) {
        this.mno_id = mno_id;
    }

    public Boolean getFallbackAttr() {
        return fallbackAttr;
    }

    public void setFallbackAttr(Boolean fallbackAttr) {
        this.fallbackAttr = fallbackAttr;
    }

    public String getMsisdn() {
        return msisdn;
    }

    public void setMsisdn(String msisdn) {
        this.msisdn = msisdn;
    }

    public String getImsi() {
        return imsi;
    }

    public void setImsi(String imsi) {
        this.imsi = imsi;
    }

    public State getState() {
        return state;
    }

    public void setState(State state) {
        this.state = state;
    }

    public String getSmdpOID() {
        return smdpOID;
    }

    public void setSmdpOID(String smdp_id) {
        this.smdpOID = smdp_id;
    }

    public String getProfileType() {
        return profileType;
    }

    public void setProfileType(String profileType) {
        this.profileType = profileType;
    }

    public Integer getAllocatedMemory() {
        return allocatedMemory;
    }

    public void setAllocatedMemory(Integer allocatedMemory) {
        this.allocatedMemory = allocatedMemory;
    }

    public Integer getFreeMemory() {
        return freeMemory;
    }

    public void setFreeMemory(Integer freeMemory) {
        this.freeMemory = freeMemory;
    }

    public List<Pol2Rule> getPol2() {
        return pol2;
    }

    public void setPol2(List<Pol2Rule> pol2) {
        this.pol2 = pol2;
    }

    public String TAR() throws Exception {
        String aid = getIsd_p_aid();
        return Utils.tarFromAid(aid);
    }

    public enum State {
        InstallInProgress, Created, Enabled, Disabled, Deleted; // This last one can't happen of course, it is only

        public static State fromCode(int code) {
            // Table 1 of SGP doc
            switch (code) {
                case 0x3: // installed,selectable,personalised
                case 0x7:
                case 0xF:
                    return Created;
                case 0x1F:
                    return Disabled;
                case 0x3F:
                    return Enabled;
                default:
                    return InstallInProgress; // ??
            }
        }
        // used for transacting internally
    }

    /**
     * @brief when a notification is received, it is sent to this. Each Transactionlog handler object for
     * a Profile status change must implement this interface
     */
    public interface HandleNotification {
        // Process a notification from eUICC
        void processNotification(NotificationMessage msg, EntityManager em) throws Exception;

        // Process the notification confirmation
        void processNotificationConfirmation(EntityManager em, TransactionType.ResponseType rtype,
                                             List<String> aids);
    }

}
