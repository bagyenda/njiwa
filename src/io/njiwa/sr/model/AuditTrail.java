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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.njiwa.common.model.RpaEntity;
import io.njiwa.common.ws.types.BaseResponseType;
import io.njiwa.common.ws.types.BaseTransactionType;

import javax.persistence.*;
import javax.xml.datatype.XMLGregorianCalendar;
import java.util.Calendar;
import java.util.Date;

/**
 * Created by bagyenda on 10/05/2017.
 */
@Entity
@Table(name = "eis_audit_trail",
        indexes = {
                @Index(columnList = "eis_id", name = "audit_trail_idx1")
        })
@SequenceGenerator(name = "eis_audit", sequenceName = "eis_audit_trail_seq")
public class AuditTrail {
    @javax.persistence.Id
    @Column(name = "id", unique = true, nullable = false, updatable = false)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "eis_audit")
    private
    Long Id;

    @Column(columnDefinition = "TEXT")
    private String eid;

    @Column(nullable = false)
    private Date operationDate;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String operationType;

    @Column(columnDefinition = "TEXT")
    private String requestorID;

    @Column(columnDefinition = "TEXT")
    private String status;
    @Column(columnDefinition = "TEXT")
    private String isdpAID;
    @Column(columnDefinition = "TEXT")
    private String iccid;
    @Column(columnDefinition = "TEXT")
    private String imei;
    @Column(columnDefinition = "TEXT")
    private String meid;

    @Column(columnDefinition = "TEXT")
    private String smsrId;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    private Eis eis;

    public AuditTrail() {
    }

    public AuditTrail(Eis eis, Date date, OperationType operation, RpaEntity us, RpaEntity requestor,
                      BaseResponseType.ExecutionStatus status, String isdpAID, String iccid, String imei,
                      String meid) {
        setEis(eis);
        setEid(eis.getEid());
        setOperationType(operation);
        if (us != null)
            setSmsrId(us.getOid());
        if (requestor != null)
            setRequestorID(requestor.getOid());
        setMeid(meid);
        setIccid(iccid);
        setIsdpAID(isdpAID);
        setImei(imei);
        setStatus(status);
        setOperationDate(date);
    }

    public AuditTrail(Eis eis, Date date, OperationType operation, RpaEntity requestor, BaseResponseType.ExecutionStatus status, String isdpAID, String iccid, String imei, String meid) {
        this(eis, date, operation, RpaEntity.getLocal(RpaEntity.Type.SMSR), requestor,
                status,
                isdpAID, iccid, imei, meid);
    }

    public AuditTrail(Eis eis, String eid, XMLGregorianCalendar date, String operationType, String requestorID,
                      BaseResponseType.ExecutionStatus status,
                      String isdpAID, String iccid, String imei, String meid, String smsrId) throws Exception {
        setEis(eis);
        setEid(eid);
        setOperationDate(date != null ? date.toGregorianCalendar().getTime() : null);
        setOperationType(operationType);
        setRequestorID(requestorID);
        setStatus(status);
        setMeid(meid);
        setImei(imei);
        setIccid(iccid);
        setIsdpAID(isdpAID);
        setSmsrId(smsrId);
    }

    public AuditTrail(Eis eis, int operationType, String requestorID,
                      String isdpAID, String iccid, String imei, String meid, String smsrId) {
        setEis(eis);
        setEid(eis.getEid());
        setOperationDate(Calendar.getInstance().getTime());
        setOperationType(operationType);
        setRequestorID(requestorID);
        setMeid(meid);
        setImei(imei);
        setIccid(iccid);
        setIsdpAID(isdpAID);
        setSmsrId(smsrId);
    }

    public AuditTrail(Eis eis, String eid, Date date, OperationType operationType, String requestorID, String
            status,
                      String isdpAID, String iccid, String imei, String meid, String smsrId) {
        setEis(eis);
        setEid(eid);
        setOperationDate(date);
        setOperationType(operationType);
        setRequestorID(requestorID);
        setStatus(status);
        setMeid(meid);
        setImei(imei);
        setIccid(iccid);
        setIsdpAID(isdpAID);
        setSmsrId(smsrId);
    }

    public static void addAuditTrail(EntityManager em, long smsrTransactionID, OperationType operation,
                                     BaseResponseType.ExecutionStatus status, String isdpAID, String iccid, String imei,
                                     String meid) {
        SmSrTransaction tr = em.find(SmSrTransaction.class, smsrTransactionID);
        BaseTransactionType trObj = (BaseTransactionType) tr.getTransObject();
        Eis eis = tr.eisEntry(em);
        RpaEntity requestor;
        if (trObj.requestingEntityId != null)
            try {
                requestor = em.find(RpaEntity.class, trObj.requestingEntityId);
            } catch (Exception ex) {
                requestor = null;
            }
        else
            requestor = null;
        AuditTrail a = new AuditTrail(eis, trObj.startDate, operation, requestor, status,
                isdpAID, iccid, imei, meid);
        eis.addToAuditTrail(em, a);

    }

    public Long getId() {
        return Id;
    }

    public void setId(Long id) {
        Id = id;
    }

    public String getEid() {
        return eid;
    }

    public void setEid(String eid) {
        this.eid = eid;
    }

    public Date getOperationDate() {
        return operationDate;
    }

    public void setOperationDate(Date operationDate) {
        this.operationDate = operationDate;
    }

    public String getOperationType() {
        return operationType;
    }

    public void setOperationType(int code) {
        setOperationType(OperationType.fromInt(code));
    }

    public void setOperationType(String operationType) {
        this.operationType = operationType;
    }

    public void setOperationType(OperationType op) {
        this.operationType = op.toString();
    }

    public String getRequestorID() {
        return requestorID;
    }

    public void setRequestorID(String requestID) {
        this.requestorID = requestID;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(BaseResponseType.ExecutionStatus status) {
        try {
            setStatus(new ObjectMapper().writeValueAsString(status));
        } catch (Exception ex) {
        }
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getIsdpAID() {
        return isdpAID;
    }

    public void setIsdpAID(String isdpAID) {
        this.isdpAID = isdpAID;
    }

    public String getIccid() {
        return iccid;
    }

    public void setIccid(String iccid) {
        this.iccid = iccid;
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

    public Eis getEis() {
        return eis;
    }

    public void setEis(Eis eis) {
        this.eis = eis;
    }

    public String getSmsrId() {
        return smsrId;
    }

    public void setSmsrId(String smsrId) {
        this.smsrId = smsrId;
    }

    public enum OperationType {

        // Notifications first, from Sec 4.1.1.11
        eUICCdeclarationNotification(1),
        ProfileChangeSucceededNotification(2),
        ProfileChangeFailedAndRollback(3),
        ProfileChangeAfterFallBack(5),
        // Then operation types from Sec 5.1.1.3.12
        CreateISDP(0x0100),
        EnableProfile(0x0200),
        DisableProfile(0x0300),
        DeleteProfile(0x0400),
        eUICCCapabilityAudit(0x0500),
        MasterDelete(0x0600),
        SetFallbackAttribute(0x0700),
        EstablishISDRkeyset(0x0800),
        FinaliseISDRhandover(0x0900),
        RFU(-1);

        private static final OperationType[] values = values();
        private int value;

        OperationType(int value) {
            this.value = value;
        }

        public static OperationType fromInt(int code) {
            for (OperationType t : values)
                if (t.value == code)
                    return t;
            return RFU;
        }

        public int toInt() {
            return value;
        }

        @Override
        public String toString() {
            return String.format("%04x", toInt());
        }
    }
}
