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


import redis.clients.jedis.Jedis;

import javax.annotation.Resource;
import javax.ejb.Stateless;
import javax.enterprise.concurrent.ManagedExecutorService;
import javax.enterprise.concurrent.ManagedScheduledExecutorService;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.persistence.EntityManager;
import javax.persistence.LockModeType;
import javax.persistence.Query;
import java.lang.reflect.ParameterizedType;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * @brief The main campaign processor class. All other classes inherit it.
 * @details A campaign entity class provides a means to periodically run campaign entities that are due for processing.
 */
@Stateless
public class GenericPeriodicProcessor<T> {

    private static final int DEFAULT_EXPIRE = 60;
    @Inject
    protected PersistenceUtility persistenceObj;
    ProcessQueue pq; //!< The processing queue


    private Class<T> persistentClass;

    @Inject
    Instance<PersistenceUtility> poTasks;

    @Resource
    private ManagedExecutorService taskExecutor; //!< Managed thread runner so we don't have to make new threads ourselves
    @Resource
    private ManagedScheduledExecutorService queueRunExecutor; //!< A periodic runner.

    private Jedis conn; //!< Connection to the REDIS server so we can ensure we never process the same job more than once simultaneously
    private String query = ""; //!< The JPA query to run
    private String name = ""; //!< The entity name
    private Map<String, Object> params = new ConcurrentHashMap<String, Object>(); //!< JPA Query parameters
    private String redis_prefix = ""; //!< REDIS prefix to ensure we two different entity modules don't trample each other
    private ScheduledFuture jobHandler = null;
    private LockModeType lockOptions; //!< Whether to lock objects fetched from the database

    public GenericPeriodicProcessor() {
        this.persistentClass = (Class<T>) ((ParameterizedType) getClass().getGenericSuperclass()).getActualTypeArguments()[0];
    }

    /**
     * @param em
     * @param template
     * @param params
     * @return
     * @brief Given a JPQL query template, make the query and add all parameters
     */
    private   Query makeQueryFromTemplate(EntityManager em, String template, Map<String, Object> params) {
        Query q = em.createQuery(template);
        for (Map.Entry<String, Object> o : params.entrySet())
            q.setParameter(o.getKey(), o.getValue());
        q.setHint("org.hibernate.cacheMode", "IGNORE");
        try {
            q.setHint("javax.persistence.cache.retrieveMode", "BYPASS"); // Force it to ignore the cache when
                        // fetching. Seems to work only for JPA 2.0 (default in Wildfly 10+ but not in 8(?)

        } catch (Exception ex) {}
        return q;
    }

    private synchronized void reconnectRedis() {
        try {
            conn.close();
        } catch (Exception ex) {

        }

        try {
            conn = Utils.redisConnect(); // Get a conneciton to redis for dealing with dups
        } catch (Exception ex) {
            Utils.lg.severe(String.format("Processor [%s]: Redis call [putkey] failed: %s", name, ex));
        }
    }

    /**
     * @param o - The entity ID
     * @return True if it is in the REDIS database. False otherwise
     * @brief Check if this entity is being processed. If so (return false) no further processing for now
     */
    private synchronized boolean putTask(long o) {
        String key = String.format("%s_%s", redis_prefix, o);

        try {
            String res = conn.set(key, "1", "NX", "EX", DEFAULT_EXPIRE);
            if (res != null && res.equalsIgnoreCase("ok"))
                return true;
        } catch (redis.clients.jedis.exceptions.JedisConnectionException a) {
            Utils.lg.severe(String.format("Processor [%s]: Redis call [putkey] failed, connection down. Will try to reconnect", name));
            reconnectRedis();
        } catch (Exception ex) {
            Utils.lg.severe(String.format("Processor [%s]: Redis call [putkey] failed: %s", name, ex));

        }
        return false;
    }

    /**
     * @param o The entity ID
     * @brief Remove the entity from the REDIS database after it has been processed
     */
    private synchronized void removeTask(long o) {
        String key = String.format("%s_%s", redis_prefix, o);
        try {
            conn.del(key);
        } catch (redis.clients.jedis.exceptions.JedisConnectionException a) {
            Utils.lg.severe(String.format("Processor [%s]: Redis call [delkey] failed, connection down. Will try to reconnect", name));
            reconnectRedis();
        } catch (Exception ex) {
            Utils.lg.severe(String.format("Processor [%s]: Redis call [delkey] failed: %s", name, ex));
            reconnectRedis();
        }
    }

    /**
     * @param lock_wait Whether to lock when fetching objects from the database
     * @param name      Name of the entities
     * @param query     The JPA query template
     * @param params    The JPA query parameters
     * @brief Start processing an entity class:
     */
    protected  void start(boolean lock_wait, String name, String query, Map<String, Object> params) {

        this.name = name;
        this.query = query;
        if (params != null)
            this.params = params;
        redis_prefix = name;


        lockOptions = lock_wait ? LockModeType.PESSIMISTIC_WRITE : LockModeType.NONE;
        reconnectRedis();

        // Start thread to process stuff at regular intervals
        pq = new ProcessQueue();
        // qThread = new Thread(pq);
        // qThread.start();

        Utils.lg.info(String.format("Starting Queue Processor [%s]...", name));
        jobHandler = queueRunExecutor.scheduleAtFixedRate(pq, ServerSettings.Constants.DEFAULT_PERIODIC_STARTUP_DELAY, (long) (ServerSettings.getQueuerunintvl() * 1000), TimeUnit.MILLISECONDS);
    }

    /**
     * @brief Stop processing the entities
     */
    protected  void stop() {
        try {
            pq.stopIt();
            Utils.lg.info(String.format("Stopped Queue Processor [%s]", name));
            jobHandler.cancel(true);
        } catch (Exception ex) {
        }
        conn.close(); // Close stuff.
    }

    /**
     * @param em  Entity Manager
     * @param obj The object/entity from the database
     * @return An object to be processed by the subclass
     * @throws Exception
     * @brief The actual processor of an entity. This is implemented by the subclass
     */
    protected Object processTask(EntityManager em, T obj) throws Exception {
        // This is overriden by subclasses
        return null;
    }

    /**
     * @param em  Entity manager
     * @param obj The object/entity from the database
     * @param res The return value of processTask()
     * @brief This method is run after each task is processed
     */
    protected void afterTask(EntityManager em, T obj, Object res) {
        // Over-ridden by subclass
    }



    /**
     * @brief The actual runner object/class.
     */
    private class ProcessQueue implements Runnable, PersistenceUtility.Runner {
        private boolean stop = false;

        @Override
        public void cleanup(boolean s) {
        }

        @Override
        public Object run(PersistenceUtility po, EntityManager em) throws Exception {
            Query query1 = makeQueryFromTemplate(em, query, params);
            Utils.lg.info(String.format("Running Queue [%s]...", name));
            List<Long> l = (List<Long>) query1.getResultList();

            // The ID must be an Long
            for (Long o : l)
                try {
                    final long objId = o;
                    if (putTask(objId)) {
                        // Make a run in trans to use, then submit it to run.

                        final PersistenceUtility.Runner ro = new PersistenceUtility.Runner() {
                            @Override
                            public Object run(PersistenceUtility po, EntityManager em) throws Exception {
                                try {

                                    T obj = (T) em.find(persistentClass, objId, lockOptions);
                                    Object res = processTask(em, obj);
                                    afterTask(em, obj, res);
                                } catch (Exception ex) {
                                    Utils.lg.warning(String.format("Error during %s task [#%s] processing: [%s] ", name,
                                                                                    objId,
                                                                                    ex));
                                    throw ex;
                                }

                                return null;
                            }

                            @Override
                            public void cleanup(boolean s) {
                                removeTask(objId); // Remove it from list.
                            }
                        };

                        try {
                            final PersistenceUtility xpo = poTasks.get();
                            taskExecutor.submit(() -> xpo.doTransaction(ro)); // Run it...
                        } catch (Exception ex) {
                            removeTask(objId); // Remove it we fail
                        }
                    }
                } catch (Exception ex) {
                    Utils.lg.severe(String.format("Error running task [%s]: %s", name, ex));
                    ex.printStackTrace();
                }
            return null;
        }

        public void run() {
            Utils.lg.info(String.format("Entered Single Queue run [%s]...", name));
            if (!stop)
                try {
                    persistenceObj.doTransaction(this);
                    Utils.lg.info(String.format("Finished single Queue run [%s]", name));
                    //  Thread.sleep((long) (Properties.getQueueRunInterval() * 1000));
                } catch (Exception ex) {
                    Utils.lg.severe(String.format("Failed queue run: %s", ex));
                }
        }

        public synchronized void stopIt() {
            stop = true;
        }
    }
}

