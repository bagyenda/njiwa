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
import io.njiwa.common.model.Key;
import io.njiwa.common.model.KeyComponent;
import io.njiwa.common.model.KeySet;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;

import javax.persistence.*;
import java.util.List;

/**
 * Created by bagyenda on 20/04/2016.
 */
@Entity
@Table(name = "securitydomains",
        indexes = {
        @Index(columnList = "eis_id", name = "sd_idx1"),
        @Index(columnList = "eis_id,aid", name = "sd_idx2",unique = true),
}
)
@SequenceGenerator(name = "securitydomains", sequenceName = "securitydomains_seq", allocationSize = 1)
@JsonIgnoreProperties(value = {"hibernateLazyInitializer", "eis"})
@DynamicUpdate
@DynamicInsert
public class SecurityDomain {

    @javax.persistence.Id
    @Column(name = "id", unique = true, nullable = false, updatable = false)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "securitydomains")
    private
    Long Id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    private
    Eis eis; // Map to EIS entry

    @Column(nullable = false)
    private
    String aid;

    @Column(nullable = false)
    private
    String sin;

    @Column(nullable = false)
    private
    String sdin;

    @Column(nullable = false)
    private
    Role role;

    @Column(nullable = true)
    private
    String TARs; // As comma-separated list
    @OneToMany(mappedBy = "sd", cascade = CascadeType.ALL, orphanRemoval = true)
    private
    List<KeySet> keysets; //!< The keys in this thingie

    public SecurityDomain() {
    }

    public SecurityDomain(String aid, String sin, String sdin, Role role, String tar, List<KeySet> keySets) {
        setAid(aid);
        setSdin(sdin);
        setSin(sin);
        setRole(role);
        setTARs(tar);

        for (KeySet k : keySets)
            k.setSd(this);
        setKeysets(keySets);
    }

    public static SecurityDomain findByTar(Eis eis, byte[] TAR) {
        try {
            String xtar = Utils.HEX.b2H(TAR);
            for (SecurityDomain s : eis.getSdList()) {
                for (String t : s.getTARsAsList())
                    if (t.equalsIgnoreCase(xtar))
                        return s;
                    // Try by AID
                if (Utils.tarFromAid(s.getAid()).equalsIgnoreCase(xtar))
                    return s;
            }
        } catch (Exception ex) {
        }
        return null;
    }

    public Long getId() {
        return Id;
    }

    public void setId(Long id) {
        Id = id;
    }

    public Eis getEis() {
        return eis;
    }

    public void setEis(Eis eis) {
        this.eis = eis;
    }

    public String getAid() {
        return aid;
    }

    public void setAid(String aid) {
        this.aid = aid;
    }

    public String getSin() {
        return sin;
    }

    public void setSin(String sin) {
        this.sin = sin;
    }

    public String getSdin() {
        return sdin;
    }

    public void setSdin(String sdin) {
        this.sdin = sdin;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }

    public String getTARs() {
        return TARs;
    }

    public void setTARs(String TARs) {
        this.TARs = TARs;
    }

    public String[] getTARsAsList() {
        String t = getTARs();
        if (t == null)
            return new String[0];
        else
            return t.split(",");
    }

    public String firstTAR() {
        try {
            return getTARsAsList()[0];
        } catch (Exception ex) {
        }

        try {
            return Utils.tarFromAid(getAid()); // Return it from AID
        } catch (Exception ex) {

        }

        return "000000";
    }

    public List<KeySet> getKeysets() {
        return keysets;
    }

    public void setKeysets(List<KeySet> keysets) {
        this.keysets = keysets;
    }

    public String description() {
        String xaid = getAid();
        String xrole = getRole().toString();
        return String.format("%s [%s]", xaid != null ? xaid : "n/a", xrole);
    }

    public  Utils.Pair<KeyComponent,KeyComponent> findFirstSCP80KeyComponents() {
        for (KeySet ks : getKeysets())
            if (ks.getType() == KeySet.Type.SCP80) {
                KeyComponent kic = null, kid = null;
                // Check for component with idx 1 (KIC) and one with idx 2 (KID)
                for (Key key : ks.getKeys()) {
                    if (key.getIndex() == Key.KIC_KEY_IDENTIFIER)
                        kic = key.findSuitableKeycomponent(KeyComponent.suitableTS102225Types);
                    else if (key.getIndex() == Key.KID_KEY_IDENTIFIER)
                        kid = key.findSuitableKeycomponent(KeyComponent.suitableTS102225Types);
                    if (kic != null && kid != null) return new Utils.Pair<>(kic, kid);
                }
            }
        return null;
    }

    public enum Role {
        ISDR, ECASD
    }


}
