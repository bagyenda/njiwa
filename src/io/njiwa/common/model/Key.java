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
import io.njiwa.sr.model.SecurityDomain;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by bagyenda on 20/04/2016.
 */
@Entity
@Table(name = "keys", uniqueConstraints = {
        @UniqueConstraint(columnNames = {"idx", "keyset_id"}, // Index must be unique in keyset. Right?!
                name = "key_idx_ct")
}, indexes = {
        @Index(columnList = "idx,keyset_id", name = "keys_idx1")
})
@SequenceGenerator(name = "keys", sequenceName = "keys_seq", allocationSize = 1)
@JsonIgnoreProperties(value = {"hibernateLazyInitializer", "keyset"})
@DynamicUpdate
@DynamicInsert
public class Key {
    // This is from Table A.1 of ETSI TS 102 225
    public static final int KIC_KEY_IDENTIFIER = 1;
    public static final int KID_KEY_IDENTIFIER = 2;
    @javax.persistence.Id
    @Column(name = "id", unique = true, nullable = false, updatable = false)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "keys")
    private
    Long Id;

    @Column(nullable = false, name = "idx")
    private
    Integer index;

    @Column(name = "kcv", columnDefinition = "text")
    private
    String checkValue;


    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    private
    KeySet keyset;

    @OneToMany(mappedBy = "key", cascade = CascadeType.ALL,orphanRemoval = true)
    private
    List<KeyComponent> keyComponents;

    public Key() {
    }

    public Key(int index, String checkValue, List<KeyComponent> keyComponents) {
        setIndex(index);
        setCheckValue(checkValue);
        try {
            for (KeyComponent c : keyComponents)
                c.setKey(this);
        } catch (Exception ex) {
        }
        setKeyComponents(keyComponents);
    }

    public Key(int index, KeyComponent keyComponent)
    {
        setIndex(index);
        List<KeyComponent> kl = new ArrayList<>();
        kl.add(keyComponent);
        keyComponent.setKey(this); // Map back
        setKeyComponents(kl);
    }
    /**
     * Find a key value from the Eis based on:
     *
     * @param sd         - The security domain
     * @param type       - Key type
     * @param idx        - Key index
     * @param typeNibble - The KIC/KID key nibble (lower nibble) as per GSM 03.48 packet format
     * @return
     * @throws Exception
     */
    public static Utils.Pair<Integer, byte[]> findKeyValue(SecurityDomain sd, KeySet.Type type, int idx,
                                                           int
                                                                   typeNibble, int keyIdentifier)
            throws
            Exception {

        KeySet k = null;

        try {
            for (KeySet keySet : sd.getKeysets())
                if (keySet.keysetType() == type && keySet.getVersion() == idx) { // A2 of ETSI TS 102 225
                    k = keySet;
                    break;
                }
        } catch (Exception ex) {

        }

        if (type == KeySet.Type.SCP80) {
            // Find first one
            for (Key key : k.getKeys())
                if (key.getIndex() == keyIdentifier) { // Table A.1 of ETSI TS 102 225
                    KeyComponent.Type kt;
                    switch (typeNibble) {
                        case 0x00:
                            kt = KeyComponent.Type.AES; // According to Sec 2.4.3 of SGP-02-3-0 AES in CBC mode is
                            // our preferred
                            break;
                        case 0x01:
                            kt = KeyComponent.Type.DES;
                            break;
                        case 0x0C:
                            kt = KeyComponent.Type.DES_ECB;
                            break;
                        case 0x05:
                        case 0x09:
                            kt = KeyComponent.Type.TripleDES_CBC;
                            break;
                        default:
                            kt = KeyComponent.Type.RFU;
                            break;
                    }
                    return new Utils.Pair<>(key.getIndex(), key.findSuitableKeycomponent(new
                            KeyComponent.Type[]{
                            kt}).byteValue());
                }
            return null;
        } else {// PSK TLS and others, get first one. XXX right?
            Key key = k.getKeys().get(0);
            return new Utils.Pair<>(key.getIndex(), key.getKeyComponents().get(0)
                    .byteValue());
        }
    }


    public KeyComponent findSuitableKeycomponent(KeyComponent.Type[] types) {
        try {
            for (KeyComponent kc : getKeyComponents())
                for (KeyComponent.Type t : types)
                    if (t == kc.getType())
                        return kc;
        } catch (Exception ex) {
        }
        return null;
    }

    @Override
    public String toString() {
        return String.format("Key [id=%s,KeySet=%s]", getIndex(), getKeyset());
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

    public String getCheckValue() {
        return checkValue;
    }

    public void setCheckValue(String checkValue) {
        this.checkValue = checkValue;
    }

    public List<KeyComponent> getKeyComponents() {
        return keyComponents;
    }

    public void setKeyComponents(List<KeyComponent> keyComponents) {
        this.keyComponents = keyComponents;
    }

    public KeySet getKeyset() {
        return keyset;
    }

    public void setKeyset(KeySet keyset) {
        this.keyset = keyset;
    }
}
