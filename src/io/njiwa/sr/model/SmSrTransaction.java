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
import com.fasterxml.jackson.databind.ObjectMapper;
import io.njiwa.common.model.TransactionType;
import io.njiwa.common.model.TransactionsStatsListener;
import io.njiwa.common.Utils;
import io.njiwa.dp.model.SmDpTransaction;
import io.njiwa.sr.transports.Transport;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;

import javax.persistence.*;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

/**
 * Stores the pending transactions
 */
@Entity
@EntityListeners(TransactionsStatsListener.class) // To record stats
@Table(name = "sr_transactions_log",
        uniqueConstraints = {@UniqueConstraint(name = "sr_tr_requestId", columnNames = {"msisdn", "requestID"})},
        indexes = {
                @Index(columnList = "msisdn,completed", name = "sr_tr_log_idx1"),
                @Index(columnList = "eis_id", name = "sr_tr_log_idx2"),
                @Index(columnList = "eid,messagetype", name = "sr_tr_log_idx4")
        })
@SequenceGenerator(name = "sr_tr_sequence", sequenceName = "sr_tr_seq", allocationSize = 1)
@DynamicInsert
@DynamicUpdate
@JsonIgnoreProperties(value = {"hibernateLazyInitializer"})
@Cacheable(false)
public class SmSrTransaction {
    @Transient
    TransactionType myObj = null;
    @javax.persistence.Id
    @Column(name = "id", unique = true, nullable = false, updatable = false)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "sr_tr_sequence")
    private
    Long Id;
    @Column(nullable = true) // Can be null, e.g. for SMSR Change
    private
    Long eis_id; // Link to the eid

    @Column(nullable = false)
    private String eid; // The EID, if any

    @Column(nullable = false, columnDefinition = "timestamp not null default current_timestamp")
    private
    Date messageDate; // When added
    @Column(nullable = false, columnDefinition = "timestamp not null default current_timestamp")
    private
    Date expires;
    @Column(nullable = false, columnDefinition = "timestamp not null default current_timestamp", insertable = false)
    private
    Date nextSend;
    @Column(nullable = false, insertable = false, columnDefinition = "timestamp not null default '1970-01-01'")
    private
    Date lastSend;
    @Column(nullable = false, insertable = false, columnDefinition = "timestamp not null default '1970-01-01'")
    private
    Date lastupdate;
    @Column(nullable = false, insertable = false, columnDefinition = "int not null default 0")
    private
    Integer numberOfAttempts; // Will be reset to zero after each Ack
    @Column(nullable = false, insertable = false, columnDefinition = "int not null default 0")
    private
    Integer numberOfTransactionsSent; // How many transactions have been sent. Including retries
    @Column(nullable = false, insertable = false, columnDefinition = "int not null default 0")
    private
    Integer retries;
    @Column(nullable = false, columnDefinition = "text not null default ''")
    private
    String messageType;
    @Column(nullable = false, columnDefinition = "text not null default ''")
    private
    String messageID;
    @Column(nullable = false, columnDefinition = "text not null default ''")
    private
    String responseEndPoint;
    @Column(nullable = false, columnDefinition = "text not null default ''")
    private
    String transactionData; // JSON-encoded, of type TransactionObject
    @Column(nullable = false, columnDefinition = "text not null default ''")
    private
    String transactionDataClassName; // The class name
    @Column(nullable = false, columnDefinition = "text not null default ''")
    private
    String msisdn; // MSISDN as used
    @Column(nullable = false, columnDefinition = "boolean not null default false")
    private Boolean moreToFollow;
    @Column(columnDefinition = "text", insertable = false, name = "requestid")
    private
    String lastrequestID;
    @Column(nullable = false, columnDefinition = "TEXT NOT NULL Default 'Ready'")
    @Enumerated(EnumType.STRING)
    private
    Status status;
    @Column(name = "transport_msg_status")
    @Enumerated(EnumType.STRING)
    private
    Transport.MessageStatus transportMessageStatus;
    @Column(name = "statuscode", columnDefinition = "TEXT")
    private
    String simStatusCode; /*!< Received SIM response code */
    @Column(name = "simresponse", columnDefinition = "TEXT")
    private
    String simResponse; /*!< Received SIM response  */
    @Column(nullable = false, columnDefinition = "boolean not null default false", insertable = false)
    private
    Boolean completed; // Whether it has been completed
    @Column(nullable = true, columnDefinition = "TEXT")
    private
    String targetAID; // Target Security Domain, by AID. Can be NULL if we are talking to the ISDR
    @Column()
    @Enumerated(EnumType.STRING)
    private
    Transport.TransportType lastTransportUsed;
    @Transient
    private Eis eis;
    @Column
    private
    Long relatesToTransaction; // The transaction which this relates to. Can be null

    @OneToMany(cascade = CascadeType.ALL,orphanRemoval = true,mappedBy = "transaction")
    private
    List<SmSrTransactionRequestId> requestIdList;

    public SmSrTransaction() {
    }

    public SmSrTransaction(EntityManager em, String messageType, String messageID, String responseEndPoint, String
            eis_id, long
                                   validityPeriod,
                           boolean moreToFollow,
                           TransactionType transObj)
            throws
            Exception {
        this(messageType, messageID, responseEndPoint, -1, validityPeriod, moreToFollow,
                transObj);
        Eis eis = Eis.findByEid(em, eis_id);
        if (eis != null)
            setEis_id(eis.getId());
        setEid(eis_id);
        setStatus(Status.Ready);
    }

    public SmSrTransaction(String messageType, String messageID, String responseEndPoint, long
            eis_id, long
                                   validityPeriod,
                           boolean moreToFollow,
                           TransactionType transObj)
            throws
            Exception {
        Calendar cal = Calendar.getInstance();
        Date mdate = cal.getTime(); // Our time
        cal.add(Calendar.SECOND, (int) validityPeriod);
        Date edate = cal.getTime();

        setMessageID(messageID);
        setMessageDate(mdate);
        setExpires(edate);
        setStatus(Status.Ready);
        setResponseEndPoint(responseEndPoint);
        setMessageType(messageType);
        setTransactionData(transObj); // Capture the object
        setMoreToFollow(moreToFollow);

        // Now look for the eid and so on
        // Eis eis = Eis.findByEid(em, eid);
        setEis_id(eis_id);

        // Look for active msisdn
        String msisdn = null;
        try {
            List<ProfileInfo> l = eis.getProfiles();
            for (ProfileInfo p : l)
                if (p.getState() == ProfileInfo.State.Enabled) {
                    msisdn = p.getMsisdn();
                    break;
                }
        } catch (Exception ex) {
        }
        setMsisdn(msisdn);
    }

    public static SmSrTransaction findTransaction(EntityManager em, String msisdn, String requestId) throws Exception {
        try {
            Long xid = em.createQuery("SELECT id from SmSrTransaction WHERE msisdn = :m and lastrequestID = " +
                            ":r ORDER by id DESC ",
                    Long.class)
                    .setParameter("m", msisdn)
                    .setParameter("r", requestId)
                    .setMaxResults(1)
                    .getSingleResult();
            if (xid == null)
                xid = SmSrTransactionRequestId.findTransaction(em, msisdn, requestId);
            return em.find(SmSrTransaction.class, xid, LockModeType.PESSIMISTIC_WRITE);
        } catch (Exception ex) {

        }
        return null;
    }

    public static SmSrTransaction findTransaction(EntityManager em, String eis_id, String messageType, Status status) {
        try {
            return em.createQuery(" from SmSrTransaction WHERE eid = :eid and messageType = :m and status = :s",
                    SmSrTransaction.class)
                    .setParameter("eid", eis_id)
                    .setParameter("m", messageType)
                    .setParameter("s", status)
                    .setMaxResults(1)
                    .getSingleResult();
        } catch (Exception ex) {

        }
        return null;
    }

    public static SmSrTransaction findfirstTransaction(EntityManager em, long eid, Status status) {
        // Find transaction given predecessor and status
        try {
            Long xId = em.createQuery("SELECT id FROM SmSrTransaction  WHERE eis_id = :i AND status = :s ORDER BY Id ASC", Long.class)
                    .setParameter("i", eid)
                    .setParameter("s", status)
                    .setMaxResults(1)
                    .getSingleResult();
            return em.find(SmSrTransaction.class, xId, LockModeType.PESSIMISTIC_WRITE);
        } catch (Exception ex) {
            String xs = ex.getMessage();
        }
        return null;
    }

    public static SmSrTransaction fromMessageID(EntityManager em, String messageID) {
        try {
            Long id = Long.parseLong(messageID, 16);
            return em.find(SmSrTransaction.class, id);
        } catch (Exception ex) {
        }
        return null;
    }

    public String genMessageIDForTrans(EntityManager em) {
        String requestID = String.format("08X", getId());
        setLastrequestID(requestID);
        setLastupdate(Calendar.getInstance().getTime());
        SmSrTransactionRequestId s = new SmSrTransactionRequestId(requestID, this, getMsisdn());
        em.persist(s);
        return requestID;
    }

    public Long getId() {
        return Id;
    }

    public void setId(Long id) {
        Id = id;
    }

    public Date getMessageDate() {
        return messageDate;
    }

    public void setMessageDate(Date messageDate) {
        this.messageDate = messageDate;
    }

    public Date getExpires() {
        return expires;
    }

    public void setExpires(Date expires) {
        this.expires = expires;
    }

    public String getMessageType() {
        return messageType;
    }

    public void setMessageType(String messageType) {
        this.messageType = messageType;
    }

    public String getMessageID() {
        return messageID;
    }

    public void setMessageID(String messageID) {
        this.messageID = messageID;
    }

    public String getResponseEndPoint() {
        return responseEndPoint;
    }

    public void setResponseEndPoint(String responseEndPoint) {
        this.responseEndPoint = responseEndPoint;
    }

    public String getTransactionData() {
        return transactionData;
    }

    public void setTransactionData(TransactionType obj) throws Exception {
        myObj = obj;
    }

    public void setTransactionData(String transactionData) {
        this.transactionData = transactionData;
    }

    public String getMsisdn() {
        return msisdn;
    }

    public void setMsisdn(String msisdn) {
        this.msisdn = msisdn;
    }

    public Boolean getCompleted() {
        return completed;
    }

    public void setCompleted(Boolean completed) {
        this.completed = completed;
    }

    public String getTransactionDataClassName() {
        return transactionDataClassName;
    }

    public void setTransactionDataClassName(String transactionDataClassName) {
        this.transactionDataClassName = transactionDataClassName;
    }

    public Long getEis_id() {
        return eis_id;
    }

    public void setEis_id(Long eid) {
        this.eis_id = eid;
    }

    public TransactionType getTransObject()  {
        if (myObj == null)
        try {
            String xcls = getTransactionDataClassName();
            String xdata = getTransactionData();
            Class cls = Class.forName(xcls);
            myObj = (TransactionType) (new ObjectMapper()).readValue(xdata, cls);
        } catch (Exception ex) {
            String xs = ex.getMessage();
        }
        return myObj;
    }

    public Eis eisEntry(EntityManager em) {
        if (eis == null)
            try {
                eis = em.createQuery("from Eis where id = :i", Eis.class)
                        .setParameter("i", getEis_id())
                        .setMaxResults(1)
                        .getSingleResult();
            } catch (Exception ex) {
            }
        return eis;
    }

    @PrePersist
    @PreUpdate
    public void updateTransients() {
        if (myObj != null)
            try {
                setTransactionDataClassName(myObj.getClass().getCanonicalName()); // Set name
                setTransactionData(new ObjectMapper().writeValueAsString(myObj));
            } catch (Exception ex) {
                String xs = ""; // Dummy
            }
    }

    public Boolean getMoreToFollow() {
        return moreToFollow;
    }

    public void setMoreToFollow(Boolean moreToFollow) {
        this.moreToFollow = moreToFollow;
    }

    public String getLastrequestID() {
        return lastrequestID;
    }

    public void setLastrequestID(String requestID) {
        this.lastrequestID = requestID;
    }

    public Date getNextSend() {
        return nextSend;
    }

    public void setNextSend(Date nextSend) {
        this.nextSend = nextSend;
    }

    public Date getLastSend() {
        return lastSend;
    }

    public void setLastSend(Date lastSend) {
        this.lastSend = lastSend;
    }

    public Integer getNumberOfAttempts() {
        return numberOfAttempts;
    }

    public void setNumberOfAttempts(Integer numberOfAttempts) {
        this.numberOfAttempts = numberOfAttempts;
    }

    public Integer getNumberOfTransactionsSent() {
        return numberOfTransactionsSent;
    }

    public void setNumberOfTransactionsSent(Integer numberOfTransactionsSent) {
        this.numberOfTransactionsSent = numberOfTransactionsSent;
    }

    public void updateStatus(EntityManager em, Status status) {
        setStatus(status);
        if (status == Status.Completed || status == Status.Error || status == Status.Failed || status == Status
                .Expired) try {
            // Look for euicc handover, and process
            Eis xeis = eisEntry(em);
            SmSrTransaction t = null;
            if (xeis.verifyPendingEuiCCHandoverTransaction(em))
                try {
                // See if we have any pending
                t = em.createQuery("from SmSrTransaction   WHERE  id <> :l AND status not in" +
                        " (:b1,:b2,:b3," +
                        ":b4)" +
                        " and nextSend > current_timestamp and eis_id = :eid", SmSrTransaction
                        .class)
                        .setParameter("l", xeis.getPendingEuiccHandoverTransaction())
                        .setParameter("b1", Status.Completed)
                        .setParameter("b2", Status.Failed)
                        .setParameter("b3", Status.Expired)
                        .setParameter("b4", Status.Error)
                        .setParameter("eid", eid)
                        .setMaxResults(1)
                        .getSingleResult();


            } catch (Exception ex) {

            }
            if (t == null) try {
                t = em.find(SmSrTransaction.class, xeis.getPendingEuiccHandoverTransaction());
                // Force
                // it out
                t.markReadyToSend();
                Utils.lg.info(String.format("Sending out euicc handover transaction [%s]", t));
                // em.flush();
            } catch (Exception ex) {

            }
        } catch (Exception ex) {
        }
    }

    public void markReadyToSend() {
        setStatus(Status.Ready);
        setRetries(0);
        setLastupdate(Calendar.getInstance().getTime());
        setNextSend(Calendar.getInstance().getTime()); // Set to go now
    }

    public void markCompleted() {
        setNextSend(Utils.infiniteDate);
        setStatus(Status.Completed);
    }

    public void markFailed() {
        setNextSend(Utils.infiniteDate);
        setStatus(Status.Failed);
    }

    public Status getStatus() {
        return status;
    }

    public void setStatus(Status status) {
        this.status = status;
    }

    public Transport.MessageStatus getTransportMessageStatus() {
        return transportMessageStatus;
    }

    public void setTransportMessageStatus(Transport.MessageStatus msgStatus) {
        this.transportMessageStatus = msgStatus;
    }

    public String getSimStatusCode() {
        return simStatusCode;
    }

    public void setSimStatusCode(String simStatusCode) {
        this.simStatusCode = simStatusCode;
    }

    /**
     * @param em
     * @return
     * @brief Return the next available transaction to send, or this one if it has more data to send...
     */
    public SmSrTransaction findNextAvailableTransaction(EntityManager em) {
        try {
            TransactionType t = getTransObject();
            if (t.hasMore())
                return this;
            long lasttid = getId();
            long eid = getEis_id();
            return em.createQuery("from SmSrTransaction   WHERE id > :l and status not in (:b1,:b2,:b3,:b4)" +
                    " and nextSend > current_timestamp and eis_id = :eid", SmSrTransaction
                    .class)
                    .setParameter("l", lasttid)
                    .setParameter("b1", Status.Completed)
                    .setParameter("b2", Status.Failed)
                    .setParameter("b3", Status.Expired)
                    .setParameter("b4", Status.Error)
                    .setParameter("eid", eid)
                    .setMaxResults(1)
                    .getSingleResult();
        } catch (Exception ex) {
            return null;
        }
    }

    public void failTransaction(EntityManager em, Status status) {
        setStatus(status);
        setNextSend(Utils.infiniteDate);
        setLastupdate(Calendar.getInstance().getTime());
        deleteTransactionRequestIds();
        // SmSrTransactionRequestId.deleteTransactionRequestIds(em, getId());
        em.flush();
    }

    public void deleteTransactionRequestIds()
    {
        setLastrequestID(null);
        List<SmSrTransactionRequestId> l = getRequestIdList();
        try {
            while (l.size() > 0) l.remove(l.get(0));
        } catch (Exception ex) {

        }
    }

    public Date getLastupdate() {
        return lastupdate;
    }

    public void setLastupdate(Date lastupdate) {
        this.lastupdate = lastupdate;
    }

    public String getSimResponse() {
        return simResponse;
    }

    public void setSimResponse(String simResponse) {
        this.simResponse = simResponse;
    }

    public Transport.TransportType getLastTransportUsed() {
        return lastTransportUsed;
    }

    public void setLastTransportUsed(Transport.TransportType transportUsed) {
        this.lastTransportUsed = transportUsed;
    }

    public String getTargetAID() {
        return targetAID;
    }

    public void setTargetAID(String targetSD) {
        this.targetAID = targetSD;
    }

    public Integer getRetries() {
        return retries;
    }

    public void setRetries(Integer retries) {
        this.retries = retries;
    }

    public Status statusFromResponse(boolean success, boolean retry) throws Exception {
        TransactionType t = getTransObject();
        boolean hasMore = t.hasMore();

        return (hasMore && success) ? SmSrTransaction.Status.Ready : // If more data,
                // send again
                success ?
                        SmSrTransaction.Status.Completed :
                        retry ? SmSrTransaction.Status.Ready :
                                SmSrTransaction.Status.Error;
    }

    public Long getRelatesToTransaction() {
        return relatesToTransaction;
    }

    public void setRelatesToTransaction(Long relatesToTransaction) {
        this.relatesToTransaction = relatesToTransaction;
    }

    public String getEid() {
        return eid;
    }

    public void setEid(String eid) {
        this.eid = eid;
    }

    @Override
    public String toString() {
        try {
            return String.format("SmsrTransaction[id=%s,eid=%s,status=%s]", getId(), getEid(), getStatus());
        } catch (Exception ex) {
            return "SMSRTransaction";
        }
    }

    public List<SmSrTransactionRequestId> getRequestIdList() {
        return requestIdList;
    }

    public void setRequestIdList(List<SmSrTransactionRequestId> requestIdList) {
        this.requestIdList = requestIdList;
    }

    /**
     * @brief Represents the current status of the transaction.
     */
    public enum Status {
        Ready, InProgress, BipWait, Sent, Error, Failed, Started, Completed, Expired, DataReceived, HttpWait;

        public static Status fromString(String val) {
            try {
                return Status.valueOf(val);
            } catch (Exception ex) {

            }
            return Ready;
        }

        public static Status fromTransStatus(Transport.MessageStatus status) {
            switch (status) {

                case BipPushSent:
                case BipPushConfirmed:
                case BipWait:
                    return BipWait;

                case HttpPushConfirmed:
                case HttpPushSent:
                case HttpWait:
                    return HttpWait;
                case NotSent:
                case SendFailed:
                    return Ready;
                case SendFailedFatal:
                    return Error;
                default:
                    return Sent;
            }

        }
    }


}
