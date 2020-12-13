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

package io.njiwa.dp.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.MapType;
import com.fasterxml.jackson.databind.type.TypeFactory;
import io.njiwa.common.model.RpaEntity;
import io.njiwa.dp.pedefinitions.*;
import io.njiwa.common.PersistenceUtility;
import io.njiwa.common.Utils;
import io.njiwa.sr.ws.types.Pol2Type;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;
import org.openmuc.jasn1.ber.BerByteArrayOutputStream;
import org.openmuc.jasn1.ber.types.BerOctetString;

import javax.persistence.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Created by bagyenda on 30/03/2017.
 * Represents a profile Template from the MNO
 */
@Entity
@Table(name = "dp_profiles", uniqueConstraints = {
        @UniqueConstraint(columnNames = {"mno_id", "iccid"}, // Index must be unique on MNO and ICCID
                name = "dp_profiles_idx_ct")
}, indexes = {
        @Index(columnList = "mno_id,iccid", name = "dp_profiles_idx1"),
        @Index(columnList = "mno_id,profile_type", name = "dp_profiles_idx2")
})
@SequenceGenerator(name = "profile", sequenceName = "dp_profiles_seq", allocationSize = 1)
@JsonIgnoreProperties(value = {"hibernateLazyInitializer"})
@DynamicUpdate
@DynamicInsert
public class ProfileTemplate {

    @javax.persistence.Id
    @Column(name = "id", unique = true, nullable = false, updatable = false)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "profile")
    private
    Long Id;
    @Column(nullable = false, name = "date_added", columnDefinition = "timestamp default current_timestamp", updatable = false, insertable = false)
    private
    Date dateAdded;
    @Column(name = "iccid", nullable = false)
    private
    String iccid;
    @Column(name = "profile_type", columnDefinition = "TEXT")
    private
    String type;
    @Column(nullable = false)
    private
    byte[] derData; // encoded list of PEs
    @Column(name = "data_source_type", nullable = false)
    @Enumerated(EnumType.STRING)
    private
    DataSourceType sourceType;
    @Column
    private
    String dataURL; // If data source type = URL

    @ElementCollection
    @CollectionTable(name = "dp_profile_parameters")
    @MapKeyColumn(name = "param", columnDefinition = "TEXT")
    @Column(name = "target_pe_type", columnDefinition = "TEXT")
    private
    Map<String, ParamTarget> parameterTypes;

    @ElementCollection
    @CollectionTable(name = "dp_profiles_supported_platforms")
    @MapKeyColumn(name = "platformVersion", columnDefinition = "TEXT")
    @Column(name = "minimum_version", columnDefinition = "TEXT")
    private
    Map<String, String> supportedPlatforms;

    @OneToMany(mappedBy = "prof", cascade = CascadeType.ALL, orphanRemoval = true)
    private
    List<ProfileData> dataList; // If type = File

    @Column(name = "major_version", nullable = false)
    private
    int major_version;

    @Column(name = "minor_version", nullable = false)
    private
    int minor_version;

    @Column(name = "required_mem", columnDefinition = "int not null default 0", nullable = false)
    private
    Integer requiredMemory;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    private
    RpaEntity mno; // Owner MNO

    @Column(name = "defaultpol2", columnDefinition = "TEXT")
    private
    String defaultPol2JSON; // as JSON

    public ProfileTemplate() {
    }

    public ProfileTemplate(RpaEntity mno, List<ProfileElement> profileElements, DataSourceType sourceType) throws Exception {
        // Profile header must be first element according to Sec 8.2 of eUICC Profile Package SimAlliance Doc
        ProfileHeader pHeader = profileElements.get(0).getHeader();

        try {
            String in = pHeader.getIccid().toString();
            String iccid = Utils.iccidFromBytes(in);
            setIccid(iccid);
        } catch (Exception ex) {

        }
        try {
            setType(pHeader.getProfileType().toString());
        } catch (Exception ex) {}

        setMajor_version((int) pHeader.getMajorVersion().value);
        setMinor_version((int) pHeader.getMinorVersion().value);
        setMno(mno);
        setDerData(toBytes(profileElements));
        setSourceType(sourceType);
    }

    /**
     * @param resp: Whether we had a fatal error (i.e stop processing), String representation of all errors,
     * @return
     * @brief Examine eUICC response, look at each PEStatus object, check if all OK, check if profile load aborted
     */
    public static Utils.Pair<Boolean, String> processEuiccResponse(EUICCResponse resp) {
        boolean res = resp.getProfileInstallationAborted() != null;
        String xs = "", sep = "";
        try {
            for (PEStatus p : resp.getPeStatus().getPEStatus()) {
                String status;
                switch ((int) p.getStatus().value) { // Sec 8.11 of eUICC Profile Package Interop Format Spec v2.0
                    case 0:
                        status = "ok";
                        break;
                    case 1:
                        status = "pe-not-supported";
                        break;
                    case 2:
                        status = "memory-failure";
                        break;
                    case 3:
                        status = "bad-values";
                        break;
                    case 4:
                        status = "not-enough-memory";
                        break;
                    case 5:
                        status = "invalid-request-format";
                        break;
                    case 6:
                        status = "invalid-parameter";
                        break;
                    case 7:
                        status = "runtime-not-supported";
                        break;
                    case 8:
                        status = "lib-not-supported";
                        break;
                    case 9:
                        status = "template-not-supported";
                        break;
                    case 10:
                        status = "feature-not-supported";
                        break;
                    case 31:
                        status = "unsupported-profile-version";
                        break;
                    default:
                        status = String.format("Error: %0x2x", p.getStatus().value);
                        break;
                }
                String err = "[Code=" + status + " ";
                if (p.getAdditionalInformation() != null)
                    err += ", AdditionalInfo" + p.getAdditionalInformation().toString();
                if (p.getIdentification() != null)
                    err += ", PeNum=" + p.getIdentification().toString();
                xs = sep + err + "]";
                sep = ", ";
            }
        } catch (Exception ex) {
        }
        if (resp.getStatusMessage() != null) {
            xs += sep + "StatusMessage=[" + resp.getStatusMessage() + "]";
            sep = ", ";
        }
        if (resp.getProfileInstallationAborted() != null)
            xs += sep + "ProfileInstallationAborted";
        return new Utils.Pair<Boolean, String>(res, xs);
    }

    public static byte[] toBytes(List<ProfileElement> profileElements) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (ProfileElement p : profileElements) {
            BerByteArrayOutputStream os = new BerByteArrayOutputStream(128, true);
            p.encode(os, true);
            out.write(os.getArray());
        }
        return out.toByteArray();
    }

    public static ProfileTemplate findByICCID(EntityManager em, String iccid, long mnoID) {
        try {
            return em.createQuery("from ProfileTemplate where iccid = :iccid and mno.id = :m", ProfileTemplate.class)
                    .setParameter("iccid", iccid)
                    .setParameter("m", mnoID)
                    .setMaxResults(1)
                    .getSingleResult();
        } catch (Exception ex) {
        }
        return null;
    }

    public static ProfileTemplate findByType(EntityManager em, String type, long mnoID) {
        try {
            return em.createQuery("from ProfileTemplate  where type = :t and mno.id = :m", ProfileTemplate.class)
                    .setParameter("t", type)
                    .setParameter("m", mnoID)
                    .setMaxResults(1)
                    .getSingleResult();
        } catch (Exception ex) {
        }
        return null;
    }

    Pol2Type pol2Rules() {
        try {
            return new ObjectMapper().readValue(getDefaultPol2JSON(), Pol2Type.class);
        } catch (Exception ex) {

        }
        return null;
    }

    public String getDefaultPol2JSON() {
        return defaultPol2JSON;
    }

    public void setDefaultPol2JSON(String defaultPol2JSON) {
        this.defaultPol2JSON = defaultPol2JSON;
    }

    public Map<String, ParamTarget> getParameterTypes() {
        return parameterTypes;
    }

    public void setParameterTypes(Map<String, ParamTarget> parameters) {
        this.parameterTypes = parameters;
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

    public String getIccid() {
        return iccid;
    }

    public void setIccid(String iccid) {
        this.iccid = iccid;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public byte[] getDerData() {
        return derData;
    }

    public void setDerData(byte[] derData) {
        this.derData = derData;
    }

    public DataSourceType getSourceType() {
        return sourceType;
    }

    public void setSourceType(DataSourceType sourceType) {
        this.sourceType = sourceType;
    }

    public String getDataURL() {
        return dataURL;
    }

    public void setDataURL(String dataURL) {
        this.dataURL = dataURL;
    }

    public List<ProfileData> getDataList() {
        return dataList;
    }

    public void setDataList(List<ProfileData> dataList) {
        this.dataList = dataList;
    }

    public Map<String, byte[]> obtainDataFromFile(EntityManager em, String eid, ConnectivityParams cp) {
        try {
            // Select the first row the matches, then update it and go
            ProfileData d = em.createQuery("from ProfileData where prof.id = :p and dateUsed is null order by dateAdded",
                    ProfileData
                            .class)
                    .setParameter("p", getId())
                    .setMaxResults(1)
                    .setLockMode(LockModeType.PESSIMISTIC_WRITE)
                    .getSingleResult();
            em.lock(d, LockModeType.PESSIMISTIC_WRITE);
            d.markUsed(eid);
            String msisdn = d.getMsisdn();
            String imsi = d.getImsi();
            Pol2Type t = pol2Rules();
            cp.set(imsi, msisdn, t);
            em.flush(); // Right??
            return d.getProfileData(); // Get the data
        } catch (Exception ex) {

        }
        return null;
    }

    private Map<String, byte[]> obtainData(EntityManager em, String eid, ConnectivityParams cp) throws Exception {
        DataSourceType t = getSourceType();

        switch (t) {
            case URL:
                Map<String, String> hdrs = new HashMap<String, String>();
                hdrs.put("X-EID", eid);
                Utils.Triple<Integer, Map<String, String>, String> out = Utils.getUrlContent(getDataURL(),
                        Utils.HttpRequestMethod.GET,
                        hdrs, null, null);
                hdrs = out.l; // Response headers
                String res = out.m;
                int code = out.k;
                if (code == 200) try {
                    String msisdn = hdrs.get("X-MSISDN");
                    String imsi = hdrs.get("X-IMSI");

                    TypeFactory f = TypeFactory.defaultInstance();
                    MapType type = f.constructMapType(HashMap.class, String.class, byte[].class);
                    cp.set(imsi, msisdn, pol2Rules());
                    return new ObjectMapper().readValue(res, type);
                } catch (Exception ex) {

                }
                return null;
            case Database:
                // From file
                return obtainDataFromFile(em, eid, cp);

        }
        return null;
    }

    public List<ProfileElement> profileElements() {
        return fromBytes(getDerData());
    }

    public static List<ProfileElement> fromBytes(byte[] data)
    {
        ByteArrayInputStream in = new ByteArrayInputStream(data);
        List<ProfileElement> pl = new ArrayList<ProfileElement>();

        while (in.available() > 0)
            try {
                ProfileElement pe = new ProfileElement();
                pe.decode(in, null);
                pl.add(pe);
            } catch (Exception ex) {
            }
        return pl;
    }

    public byte[] performDataPreparation(PersistenceUtility po, final String eid, final ConnectivityParams cp) throws
            Exception {
        return po.doTransaction(new PersistenceUtility.Runner<byte[]>() {
            @Override
            public byte[] run(PersistenceUtility po, EntityManager em) throws Exception {
                return performDataPreparation(em, eid, cp);
            }

            @Override
            public void cleanup(boolean success) {

            }
        });
    }

    public byte[] performDataPreparation(EntityManager em, String eid, ConnectivityParams cp) throws Exception {
        List<ProfileElement> profileElements = profileElements();
        Map<String, byte[]> data = obtainData(em, eid, cp);
        Map<String, ParamTarget> ptypes = getParameterTypes();

        // Make a map of TargetType => List<Pair(key,value)>
        Map<ParamTarget, List<Utils.Pair<byte[], byte[]>>> replacements = new HashMap<ParamTarget, List<Utils.Pair<byte[],
                byte[]>>>() {
            {
                put(ParamTarget.FILEDATA, new ArrayList<Utils.Pair<byte[], byte[]>>());
                put(ParamTarget.KEYDATA, new ArrayList<Utils.Pair<byte[], byte[]>>());
                put(ParamTarget.NAA, new ArrayList<Utils.Pair<byte[], byte[]>>());
                put(ParamTarget.NONSTANDARD, new ArrayList<Utils.Pair<byte[], byte[]>>());
                put(ParamTarget.PIN, new ArrayList<Utils.Pair<byte[], byte[]>>());
            }
        };

        if (data != null && ptypes != null)
            for (Map.Entry<String, byte[]> e : data.entrySet()) {
                ParamTarget target = ptypes.get(e.getKey());
                if (target == null)
                    target = ParamTarget.FILEDATA;
                List<Utils.Pair<byte[], byte[]>> l = replacements.get(target);
                l.add(new Utils.Pair<byte[], byte[]>(e.getKey().getBytes(StandardCharsets.UTF_8), e.getValue()));
            }
        // Search the PE and modify
        if (ptypes != null)
            for (ProfileElement p : profileElements)
                ParamTarget.patchPE(p, replacements);

        return toBytes(profileElements);
    }

    public int getMajor_version() {
        return major_version;
    }

    public void setMajor_version(int major_version) {
        this.major_version = major_version;
    }

    public int getMinor_version() {
        return minor_version;
    }

    public void setMinor_version(int minor_version) {
        this.minor_version = minor_version;
    }

    public Integer getRequiredMemory() {
        return requiredMemory;
    }

    public void setRequiredMemory(Integer requiredMemory) {
        this.requiredMemory = requiredMemory;
    }

    public Map<String, String> getSupportedPlatforms() {
        return supportedPlatforms;
    }

    public void setSupportedPlatforms(Map<String, String> supportedPlatforms) {
        this.supportedPlatforms = supportedPlatforms;
    }

    public RpaEntity getMno() {
        return mno;
    }

    public void setMno(RpaEntity mno) {
        this.mno = mno;
    }

    public enum ParamTarget {
        FILEDATA, NAA, PIN, NONSTANDARD, KEYDATA;

        protected static void patchString(BerOctetString s, byte[] key, byte[] value) {
            byte[] repl = Utils.replace(s.value, key, value);
            if (repl != null)
                s.value = repl; // Change it.
        }

        protected static void patchString(BerOctetString s, List<Utils.Pair<byte[], byte[]>> l) {
            if (l != null)
                for (Utils.Pair<byte[], byte[]> pset : l)
                    patchString(s, pset.k, pset.l);
        }

        protected static void patchFILE(File pe, byte[] key, byte[] value) {
            List<File.CHOICE> l = pe.getCHOICE();
            BerOctetString s;
            if (l != null)
                for (File.CHOICE c : l)
                    if ((s = c.getFillFileContent()) != null)
                        patchString(s, key, value);
        }

        protected static void patchFILE(File pe, List<Utils.Pair<byte[], byte[]>> pl) {
            List<File.CHOICE> l = pe.getCHOICE();
            BerOctetString s;
            if (l != null)
                for (File.CHOICE c : l)
                    if ((s = c.getFillFileContent()) != null)
                        patchString(s, pl);
        }

        public static void patchPE(ProfileElement pe, Map<ParamTarget, List<Utils.Pair<byte[], byte[]>>> replacements) throws Exception {


            if (pe.getNonStandard() != null && pe.getNonStandard().getContent() != null)
                patchString(pe.getNonStandard().getContent(), replacements.get(NONSTANDARD));
// Process NAA data
            List<Utils.Pair<byte[], byte[]>> naaList = replacements.get(NAA);
            if (pe.getAkaParameter() != null) {
                PEAKAParameter aka = pe.getAkaParameter();
                if (aka.getAlgoConfiguration() != null) {
                    if (aka.getAlgoConfiguration().getAlgoParameter() != null) {
                        if (aka.getAlgoConfiguration().getAlgoParameter().getKey() != null)
                            patchString(aka.getAlgoConfiguration().getAlgoParameter().getKey(), naaList);
                        if (aka.getAlgoConfiguration().getAlgoParameter().getOpc() != null)
                            patchString(aka.getAlgoConfiguration().getAlgoParameter().getOpc(), naaList);
                        if (aka.getAlgoConfiguration().getAlgoParameter().getRotationConstants() != null)
                            patchString(aka.getAlgoConfiguration().getAlgoParameter().getRotationConstants(), naaList);
                        if (aka.getAlgoConfiguration().getAlgoParameter().getXoringConstants() != null)
                            patchString(aka.getAlgoConfiguration().getAlgoParameter().getXoringConstants(), naaList);

                        PEAKAParameter.SqnInit s = aka.getSqnInit();
                        if (s.getBerOctetString() != null)
                            for (BerOctetString x : s.getBerOctetString())
                                patchString(x, naaList);
                    }
                }
            }
            if (pe.getCdmaParameter() != null) {
                if (pe.getCdmaParameter().getSsd() != null)
                    patchString(pe.getCdmaParameter().getSsd(), naaList);
                if (pe.getCdmaParameter().getAuthenticationKey() != null)
                    patchString(pe.getCdmaParameter().getAuthenticationKey(), naaList);
                if (pe.getCdmaParameter().getHrpdAccessAuthenticationData() != null)
                    patchString(pe.getCdmaParameter().getHrpdAccessAuthenticationData(), naaList);
                if (pe.getCdmaParameter().getMobileIPAuthenticationData() != null)
                    patchString(pe.getCdmaParameter().getMobileIPAuthenticationData(), naaList);
                if (pe.getCdmaParameter().getSimpleIPAuthenticationData() != null)
                    patchString(pe.getCdmaParameter().getSimpleIPAuthenticationData(), naaList);
            }
            // Process Keydata
            List<Utils.Pair<byte[], byte[]>> keydataList = replacements.get(KEYDATA);
            if (pe.getSecurityDomain() != null) {
                PESecurityDomain sd = pe.getSecurityDomain();
                PESecurityDomain.KeyList keyList = sd.getKeyList();
                List<KeyObject> keyObjects = keyList != null ? keyList.getKeyObject() : new
                        ArrayList<KeyObject>();
                for (KeyObject ko : keyObjects) {
                    KeyObject.KeyCompontents kc = ko.getKeyCompontents();
                    List<KeyObject.KeyCompontents.SEQUENCE> sl = kc != null ? kc.getSEQUENCE() : new
                            ArrayList<KeyObject.KeyCompontents.SEQUENCE>();
                    for (KeyObject.KeyCompontents.SEQUENCE s : sl)
                        if (s.getKeyData() != null)
                            patchString(s.getKeyData(), keydataList); // Patch only values...
                }
            }
            // Process File data
            List<Utils.Pair<byte[], byte[]>> fdataList = replacements.get(FILEDATA);
            // Only touch certain elements...
            if (pe.getGenericFileManagement() != null) {
                PEGenericFileManagement p = pe.getGenericFileManagement();
                List<FileManagement> l = (p.getFileManagementCMD() != null) ? p.getFileManagementCMD()
                        .getFileManagement() : new ArrayList<FileManagement>();
                List<FileManagement.CHOICE> cl;
                BerOctetString s;
                for (FileManagement fm : l)
                    if ((cl = fm.getCHOICE()) != null)
                        for (FileManagement.CHOICE c : cl)
                            if ((s = c.getFillFileContent()) != null)
                                patchString(s, fdataList);
            }
            File fp;
            // Patch files
            if (pe.getMf() != null) {
                PEMF mf = pe.getMf();
                // Patch files one by one
                if ((fp = mf.getEfArr()) != null)
                    patchFILE(fp, fdataList);
                if ((fp = mf.getEfDir()) != null)
                    patchFILE(fp, fdataList);
                if ((fp = mf.getEfIccid()) != null)
                    patchFILE(fp, fdataList);
                if ((fp = mf.getEfUmpc()) != null)
                    patchFILE(fp, fdataList);
            }
            if (pe.getCd() != null) {
                if ((fp = pe.getCd().getEfIcon()) != null)
                    patchFILE(fp, fdataList);
                if ((fp = pe.getCd().getEfLaunchpad()) != null)
                    patchFILE(fp, fdataList);
            }
            // Made using Awk script template (where xx contains the defined EFs/DFs from the relevant java
            // class -- change var "top"):
            //awk '{print $3}' < xx | grep 'ef' | awk 'BEGIN {top="Usim"; print "if (pe.get"top"() != null)
            // {" } {x=toupper(substr($1,1,1)) substr($1,2); print "if ((fp = pe.get"top"().get"x"()) !=
            // null) patchFILE(fp,fdataList);" } END {print "}" }'
            if (pe.getTelecom() != null) {
                if ((fp = pe.getTelecom().getEfArr()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getTelecom().getEfRma()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getTelecom().getEfSume()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getTelecom().getEfIceDn()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getTelecom().getEfIceFf()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getTelecom().getEfPsismsc()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getTelecom().getEfImg()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getTelecom().getEfIidf()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getTelecom().getEfIceGraphics()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getTelecom().getEfLaunchScws()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getTelecom().getEfIcon()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getTelecom().getEfPbr()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getTelecom().getEfExt1()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getTelecom().getEfAas()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getTelecom().getEfGas()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getTelecom().getEfPsc()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getTelecom().getEfCc()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getTelecom().getEfPuid()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getTelecom().getEfIap()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getTelecom().getEfAdn()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getTelecom().getEfPbc()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getTelecom().getEfAnr()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getTelecom().getEfPuri()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getTelecom().getEfEmail()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getTelecom().getEfSne()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getTelecom().getEfUid()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getTelecom().getEfGrp()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getTelecom().getEfCcp1()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getTelecom().getEfMml()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getTelecom().getEfMmdf()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getTelecom().getEfMlpl()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getTelecom().getEfMspl()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getTelecom().getEfMmssmode()) != null) patchFILE(fp, fdataList);
            }
            if (pe.getUsim() != null) {
                if ((fp = pe.getUsim().getEfImsi()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getUsim().getEfArr()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getUsim().getEfKeys()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getUsim().getEfKeysPS()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getUsim().getEfHpplmn()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getUsim().getEfUst()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getUsim().getEfFdn()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getUsim().getEfSms()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getUsim().getEfSmsp()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getUsim().getEfSmss()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getUsim().getEfSpn()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getUsim().getEfEst()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getUsim().getEfStartHfn()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getUsim().getEfThreshold()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getUsim().getEfPsloci()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getUsim().getEfAcc()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getUsim().getEfFplmn()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getUsim().getEfLoci()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getUsim().getEfAd()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getUsim().getEfEcc()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getUsim().getEfNetpar()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getUsim().getEfEpsloci()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getUsim().getEfEpsnsc()) != null) patchFILE(fp, fdataList);
            }
            if (pe.getOptUsim() != null) {
                if ((fp = pe.getOptUsim().getEfLi()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfAcmax()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfAcm()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfGid1()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfGid2()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfMsisdn()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfPuct()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfCbmi()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfCbmid()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfSdn()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfExt2()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfExt3()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfCbmir()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfPlmnwact()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfOplmnwact()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfHplmnwact()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfDck()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfCnl()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfSmsr()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfBdn()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfExt5()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfCcp2()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfExt4()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfAcl()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfCmi()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfIci()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfOci()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfIct()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfOct()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfVgcs()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfVgcss()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfVbs()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfVbss()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfEmlpp()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfAaem()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfHiddenkey()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfPnn()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfOpl()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfMbdn()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfExt6()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfMbi()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfMwis()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfCfis()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfExt7()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfSpdi()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfMmsn()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfExt8()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfMmsicp()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfMmsup()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfMmsucp()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfNia()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfVgcsca()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfVbsca()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfGbabp()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfMsk()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfMuk()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfEhplmn()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfGbanl()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfEhplmnpi()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfLrplmnsi()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfNafkca()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfSpni()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfPnni()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfNcpIp()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfUfc()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfNasconfig()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfUicciari()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfPws()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfFdnuri()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfBdnuri()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfSdnuri()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfIwl()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfIps()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptUsim().getEfIpd()) != null) patchFILE(fp, fdataList);
            }
            if (pe.getIsim() != null) {
                if ((fp = pe.getIsim().getEfImpi()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getIsim().getEfImpu()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getIsim().getEfDomain()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getIsim().getEfIst()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getIsim().getEfAd()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getIsim().getEfArr()) != null) patchFILE(fp, fdataList);
            }
            if (pe.getOptIsim() != null) {
                if ((fp = pe.getOptIsim().getEfPcscf()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptIsim().getEfSms()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptIsim().getEfSmsp()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptIsim().getEfSmss()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptIsim().getEfSmsr()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptIsim().getEfGbabp()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptIsim().getEfGbanl()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptIsim().getEfNafkca()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptIsim().getEfUicciari()) != null) patchFILE(fp, fdataList);
            }
            if (pe.getPhonebook() != null) {
                if ((fp = pe.getPhonebook().getEfPbr()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getPhonebook().getEfExt1()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getPhonebook().getEfAas()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getPhonebook().getEfGas()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getPhonebook().getEfPsc()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getPhonebook().getEfCc()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getPhonebook().getEfPuid()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getPhonebook().getEfIap()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getPhonebook().getEfAdn()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getPhonebook().getEfPbc()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getPhonebook().getEfAnr()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getPhonebook().getEfPuri()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getPhonebook().getEfEmail()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getPhonebook().getEfSne()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getPhonebook().getEfUid()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getPhonebook().getEfGrp()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getPhonebook().getEfCcp1()) != null) patchFILE(fp, fdataList);
            }
            if (pe.getGsmAccess() != null) {
                if ((fp = pe.getGsmAccess().getEfKc()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getGsmAccess().getEfKcgprs()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getGsmAccess().getEfCpbcch()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getGsmAccess().getEfInvscan()) != null) patchFILE(fp, fdataList);
            }
            if (pe.getCsim() != null) {
                if ((fp = pe.getCsim().getEfArr()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getCsim().getEfCallCount()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getCsim().getEfImsiM()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getCsim().getEfImsiT()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getCsim().getEfTmsi()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getCsim().getEfAh()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getCsim().getEfAop()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getCsim().getEfAloc()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getCsim().getEfCdmahome()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getCsim().getEfZnregi()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getCsim().getEfSnregi()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getCsim().getEfDistregi()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getCsim().getEfAccolc()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getCsim().getEfTerm()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getCsim().getEfAcp()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getCsim().getEfPrl()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getCsim().getEfRuimid()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getCsim().getEfCsimSt()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getCsim().getEfSpc()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getCsim().getEfOtapaspc()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getCsim().getEfNamlock()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getCsim().getEfOta()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getCsim().getEfSp()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getCsim().getEfEsnMeidMe()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getCsim().getEfLi()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getCsim().getEfUsgind()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getCsim().getEfAd()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getCsim().getEfMaxPrl()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getCsim().getEfSpcs()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getCsim().getEfMecrp()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getCsim().getEfHomeTag()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getCsim().getEfGroupTag()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getCsim().getEfSpecificTag()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getCsim().getEfCallPrompt()) != null) patchFILE(fp, fdataList);
            }
            if (pe.getOptCsim() != null) {
                if ((fp = pe.getOptCsim().getEfSsci()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfFdn()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfSms()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfSmsp()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfSmss()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfSsfc()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfSpn()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfMdn()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfEcc()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfMe3gpdopc()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEf3gpdopm()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfSipcap()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfMipcap()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfSipupp()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfMipupp()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfSipsp()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfMipsp()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfSippapss()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfPuzl()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfMaxpuzl()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfHrpdcap()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfHrpdupp()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfCsspr()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfAtc()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfEprl()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfBcsmscfg()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfBcsmspref()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfBcsmstable()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfBcsmsp()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfBakpara()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfUpbakpara()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfMmsn()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfExt8()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfMmsicp()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfMmsup()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfMmsucp()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfAuthCapability()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEf3gcik()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfDck()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfGid1()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfGid2()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfCdmacnl()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfSfEuimid()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfEst()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfHiddenKey()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfLcsver()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfLcscp()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfSdn()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfExt2()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfExt3()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfIci()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfOci()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfExt5()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfCcp2()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfApplabels()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfModel()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfRc()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfSmscap()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfMipflags()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEf3gpduppext()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfIpv6cap()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfTcpconfig()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfDgc()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfWapbrowsercp()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfWapbrowserbm()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfMmsconfig()) != null) patchFILE(fp, fdataList);
                if ((fp = pe.getOptCsim().getEfJdl()) != null) patchFILE(fp, fdataList);
            }
            // Process PIN data
            List<Utils.Pair<byte[], byte[]>> pinListData = replacements.get(PIN);
            if (pe.getPinCodes() != null && pe.getPinCodes().getPinCodes() != null) {
                // fix them
                PEPINCodes.PinCodes.Pinconfig p = pe.getPinCodes().getPinCodes().getPinconfig();

                List<PINConfiguration> pl = p != null ? p.getPINConfiguration() : new ArrayList<PINConfiguration>();
                for (PINConfiguration pconf : pl)
                    if (pconf.getPinValue() != null)
                        patchString(pconf.getPinValue(), pinListData);
            }
            if (pe.getPukCodes() != null && pe.getPukCodes().getPukCodes() != null) {
                PEPUKCodes.PukCodes p = pe.getPukCodes().getPukCodes();
                List<PUKConfiguration> pl = p != null ? p.getPUKConfiguration() : new
                        ArrayList<>();
                for (PUKConfiguration puk : pl)
                    if (puk.getPukValue() != null)
                        patchString(puk.getPukValue(), pinListData);
            }
        }

    }

    public enum DataSourceType {
        URL, Database
    }

    public interface ConnectivityParams {
        void set(String imsi, String msisdn, Pol2Type pol2);
    }
}
