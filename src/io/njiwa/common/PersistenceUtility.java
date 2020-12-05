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

package io.njiwa.common;

import javax.annotation.Resource;
import javax.ejb.Stateless;
import javax.ejb.TransactionManagement;
import javax.ejb.TransactionManagementType;
import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.EntityTransaction;
import javax.persistence.PersistenceUnit;
import javax.transaction.UserTransaction;



 /** @brief JPA wrapper to help with database transactions
 *
 * @details
 *
 *  We need this class because sometimes we want to ensure that our JPA calls run within a well-controlled database transaction.
 *  May be there is a better way, but we can't sometimes wait for the container to decide when to commit data to the underlying store.
 *  So in our case we provide a convenience whereby users/clients can encapsulate logic so it runs within a DB transaction.
 */


@Stateless
@TransactionManagement(TransactionManagementType.BEAN)
public class PersistenceUtility {

    @PersistenceUnit
    EntityManagerFactory factory; //!< Inject a factory manager creator

    @Resource
    UserTransaction transaction; //!< Inject the thread level transaction stuff

     /**
     * @brief This is the main interface that is used to create anonymous classes that we can execute in a transaction
     */
    public  interface Runner<T> {
         T run(PersistenceUtility po, EntityManager em) throws  Exception;
         default void cleanup(boolean success) {}
    }

    /**
     * @brief this is the main function that runs some logic in a  synchronous transaction. It will open a new transaction,
     *  execute the code given and close/commit the transaction synchronously.
     * @param o
     * @return
     */
    public   <T> T doTransaction(Runner<T> o)
    {
        T res = null;
        EntityManager em = null;
        UserTransaction transaction = this.transaction;
        EntityManagerFactory factory = this.factory;
        boolean success = false;
        EntityTransaction tx = null;
        try {

           transaction.begin(); // Begin

            em = factory.createEntityManager();
            // tx = em.getTransaction();
            // tx.begin();
            res = o.run(this, em);
            em.flush();
           // em.getEntityManagerFactory().getCache().evictAll();
           // em.clear();
           // em.close();
           // em = null;
            transaction.commit(); // commit
            // tx.commit();
            success = true;
        } catch (Exception ex) {
            // if ( tx != null && tx.isActive() ) tx.rollback();
            Utils.lg.severe(String.format("doTransaction failed: %s", ex));
           // res = null;
            try {
                transaction.rollback();
            } catch (Exception ex2) {
                Utils.lg.severe(String.format("doTransaction rollback failed: %s", ex2));
            }
        } finally {
            try {
                o.cleanup(success); // Finally, cleanup
            } catch (Exception ex) {}
           if (em != null)
                em.close();
        }

        return res;
    }



 }
