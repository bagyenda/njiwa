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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.njiwa.common.PersistenceUtility;
import io.njiwa.common.Utils;
import io.njiwa.common.model.RpaEntity;
import io.njiwa.common.model.TransactionType;
import io.njiwa.common.model.TransactionsStatsListener;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;

import javax.persistence.*;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * Created by bagyenda on 05/04/2017.
 */
@Entity
@EntityListeners(TransactionsStatsListener.class)
@Table(name = "dp_transactions_log",
        indexes = {
                @Index(columnList = "euicc", name = "dp_tr_eid_idx1"),
                @Index(columnList = "euicc,isdp_id", name = "dp_tr_eid_idx2")
        })
@SequenceGenerator(name = "dp_tr_sequence", sequenceName = "dp_tr_seq")
@DynamicInsert
@DynamicUpdate
@Cacheable(false)
public class SmDpTransaction {

    @Id
    @Column(name = "id", unique = true, nullable = false, updatable = false)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "dp_tr_sequence")
    private
    Long Id;
    @Column(nullable = false)
    private
    Long euicc;
    @Column(nullable = false, columnDefinition = "TEXT NOT NULL", name = "requestID")
    private
    String requestID; // The request ID when we forward the request
    @Column(nullable = false)
    private
    Date messageDate; // When added
    @Column(nullable = false)
    private
    Date expires;
    @Column(nullable = false, insertable = false, columnDefinition = "timestamp not null default current_timestamp")
    private
    Date lastResponse;
    @Column(nullable = false, insertable = false, columnDefinition = "timestamp not null default '1970-01-01'")
    private
    Date lastSend;
    @Column(nullable = false, columnDefinition = "timestamp not null default '1970-01-01'")
    private
    String transactionType; // The textual representation of the transaction type
    @Column(nullable = false, columnDefinition = "text not null default ''")
    private
    String transactionData; // JSON-encoded, of type TransactionObject
    @Column(nullable = false, columnDefinition = "text not null default ''")
    private
    String transactionDataClassName; // The class name
    @ManyToOne(fetch = FetchType.LAZY, optional = true)
    private
    ISDP isdp; // Link to the profile we are working on, if any
    @Column(name = "state", nullable = false)
    @Enumerated(EnumType.STRING)
    private
    Status status;
    @Column(nullable = false)
    private
    Long smsrId; // The Id of the SM-SR we are talking to. Note that the caller is stored in the object!
    @Transient
    private
    TransactionType myObj;

    @OneToMany(cascade = CascadeType.ALL,orphanRemoval = true,mappedBy = "tr")
    private
    List<SmDpTransactionResponse> responses;

    public SmDpTransaction() {
    }

    public SmDpTransaction(RpaEntity requestor,
                           long euicc, long validity, TransactionType tObj) {
        Calendar cal = Calendar.getInstance();
        setMessageDate(cal.getTime());
        cal.add(Calendar.SECOND, (int) validity);
        setExpires(cal.getTime());


        setEuicc(euicc);
        setStatus(Status.Ready);


        if (requestor != null)
            tObj.requestingEntityId = requestor.getId();
        setTransObect(tObj);
        setTransactionType(tObj.getClass().getName()); // Use the name

        // setRequestID(UUID.randomUUID().toString()); // Make a random UUID
    }

    // Find a message from the request ID
    public static SmDpTransaction findbyRequestID(EntityManager em, String requestMessageID) {
        try {
            // Extract UUID and ID
            int idx = requestMessageID.lastIndexOf('-');
            if (idx <= 0)
                throw new Exception("Invalid request ID format");
            long id = Long.parseLong(requestMessageID.substring(idx + 1));
            String rId = requestMessageID.substring(0, idx);
            return em.createQuery("from SmDpTransaction where id = :i and requestID = :r", SmDpTransaction.class)
                    .setParameter("i", id)
                    .setParameter("r", rId)
                    .setMaxResults(1)
                    .getSingleResult();
        } catch (Exception ex) {
            Utils.lg.severe(String.format("Failed to find SmDp Transaction ID for request message ID [%s]: %s ",
                    requestMessageID, ex));
        }
        return null;
    }

    public static SmDpTransaction findbyRequestID(PersistenceUtility po, final String requestMessageID) {
        return po.doTransaction(new PersistenceUtility.Runner<SmDpTransaction>() {
            @Override
            public SmDpTransaction run(PersistenceUtility po, EntityManager em) throws Exception {
                return findbyRequestID(em, requestMessageID);
            }

            @Override
            public void cleanup(boolean success) {

            }
        });
    }



    public Long getId() {
        return Id;
    }

    public void setId(Long id) {
        Id = id;
    }

    public Long getEuicc() {
        return euicc;
    }

    public void setEuicc(Long euicc) {
        this.euicc = euicc;
    }

    public String getRequestID() {
        return requestID;
    }

    public void setRequestID(String requestID) {
        this.requestID = requestID;
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

    public Date getLastResponse() {
        return lastResponse;
    }

    public void setLastResponse(Date lastResponse) {
        this.lastResponse = lastResponse;
    }

    public Date getLastSend() {
        return lastSend;
    }

    public void setLastSend(Date lastSend) {
        this.lastSend = lastSend;
    }

    public String getTransactionType() {
        return transactionType;
    }

    public void setTransactionType(String transactionType) {
        this.transactionType = transactionType;
    }

    public String getTransactionData() {
        return transactionData;
    }

    public void setTransactionData(String transactionData) {
        this.transactionData = transactionData;
    }

    public String getTransactionDataClassName() {
        return transactionDataClassName;
    }

    public void setTransactionDataClassName(String transactionDataClassName) {
        this.transactionDataClassName = transactionDataClassName;
    }

    public Status getStatus() {
        return status;
    }

    public void setStatus(Status status) {
        this.status = status;
    }

    public void setTransObect(TransactionType myObj) {
        this.myObj = myObj;
    }

    public TransactionType transactionObject()
    {
        if (myObj == null)
        try {
            Class cls = Class.forName(getTransactionDataClassName());
            myObj = (TransactionType)new ObjectMapper().readValue(getTransactionData(),cls);
        } catch (Exception ex) {
        }
        return myObj;
    }

    public ISDP getIsdp() {
        return isdp;
    }

    public void setIsdp(ISDP isdp) {
        this.isdp = isdp;
    }

    public Long getSmsrId() {
        return smsrId;
    }

    public void setSmsrId(Long smsrId) {
        this.smsrId = smsrId;
    }

    @PrePersist
    public void updateTransients() {
        if (myObj != null)
            try {
                setTransactionDataClassName(myObj.getClass().getCanonicalName()); // Set name
                setTransactionData(new ObjectMapper().writeValueAsString(myObj));
            } catch (Exception ex) {
                String xs = ""; // Dummy
            }
    }

    public String newRequestMessageID() {
        long xid = getId();
        String rId = UUID.randomUUID().toString();

        String requestID = rId + "-" + xid;
        setRequestID(requestID);
        return requestID;
    }

    public void recordResponse(EntityManager em, String operationType, String response, boolean
            isSuccess) {
        Date now = Calendar.getInstance().getTime();

        setLastResponse(now);
        setStatus( isSuccess ? Status.Ready : Status.Failed);

        SmDpTransactionResponse resp = new SmDpTransactionResponse(this, operationType, response, isSuccess);
        em.persist(resp);
    }

    public void recordResponse(PersistenceUtility po, final String operation, final String response, final TransactionType.ResponseType
            responseType)
    {
        po.doTransaction(new PersistenceUtility.Runner<Object>() {
            @Override
            public Object run(PersistenceUtility po, EntityManager em) throws Exception {
                recordResponse(em,operation,response,responseType == TransactionType.ResponseType.SUCCESS);
                return null;
            }

            @Override
            public void cleanup(boolean success) {

            }
        });
    }

    public List<SmDpTransactionResponse> getResponses() {
        return responses;
    }

    public void setResponses(List<SmDpTransactionResponse> responses) {
        this.responses = responses;
    }

    public enum Status {
        Ready, Sent, Error, Failed, Completed
    }
}
