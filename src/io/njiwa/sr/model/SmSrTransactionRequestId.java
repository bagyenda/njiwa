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

import javax.persistence.*;
import java.util.Date;

/**
 * Created by bagyenda on 28/09/2016.
 */
@Entity
@Table(name="sr_transaction_requestids_log",
        indexes = {
                @Index(columnList = "requestid,recipient",name="tr_req_idx1"),
                @Index(columnList = "transaction_id", name="tr_req_idx2")
        }

)
@SequenceGenerator(name="tr_req_seq", sequenceName = "transaction_req_ids_seq", allocationSize = 1)
public class SmSrTransactionRequestId {
    @javax.persistence.Id
    @Column(name = "id", unique = true, nullable = false, updatable = false)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "tr_req_seq")
    private
    Long id;

    @Column(nullable = false, name = "date_added", columnDefinition = "timestamp default current_timestamp", updatable = false, insertable = false)
    private
    Date dateAdded;

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    private SmSrTransaction transaction;


    @Column(nullable = false, columnDefinition = "TEXT NOT NULL")
    private
    String recipient;

    @Column(nullable = false, name="requestid", columnDefinition = "TEXT NOT NULL DEFAULT ''")
    private
    String requestid = "";

    public SmSrTransactionRequestId() {}

    public SmSrTransactionRequestId(String requestid, SmSrTransaction tr, String msisdn)
    {
        setRecipient(msisdn);
        setRequestid(requestid);
        setTransaction(tr);
    }


    public static long findTransaction(EntityManager em, String msisdn, String requestId) throws Exception {
        return em.createQuery("SELECT transaction.id from SmSrTransactionRequestId WHERE recipient = :m and requestid = " +
                ":r ORDER by id DESC ",
                Long.class)
                .setParameter("m",msisdn)
                .setParameter("r",requestId)
                .setMaxResults(1)
                .getSingleResult();
    }

    public static void deleteTransactionRequestIds(EntityManager em, long transId)
    {
        em.createQuery("DELETE FROM SmSrTransactionRequestId  WHERE transaction.id = :i")
                .setParameter("i", transId)
                .executeUpdate();
        em.createQuery("UPDATE SmSrTransaction  SET lastrequestID = null  WHERE  id = :i")
                .setParameter("i",transId)
                .executeUpdate();
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Date getDateAdded() {
        return dateAdded;
    }

    public void setDateAdded(Date dateAdded) {
        this.dateAdded = dateAdded;
    }

    public SmSrTransaction getTransaction() {
        return transaction;
    }

    public void setTransaction(SmSrTransaction transaction) {
        this.transaction = transaction;
    }

    public String getRecipient() {
        return recipient;
    }

    public void setRecipient(String recipient) {
        this.recipient = recipient;
    }

    public String getRequestid() {
        return requestid;
    }

    public void setRequestid(String requestid) {
        this.requestid = requestid;
    }
}
