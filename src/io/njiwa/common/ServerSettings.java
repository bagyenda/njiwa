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

import io.njiwa.common.model.ServerConfigurations;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.persistence.EntityManager;
import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;


/**
 * @brief This is the  configurations handler class. All configurations are loaded once at startup.
 */
public class ServerSettings {

    public static final String BASEDEPLOYMENTURI = "base_deployment_uri";
    // Conf var names
    private static final String MYHOSTNAME = "hostname";
    private static final String MYPORT = "myport";
    private static final String MAXBATCHQSIZE = "maximum_batch_queue_size";
    private static final String MAXTHREADS = "max_threads";

    private static final String QUEUERUNINTVL = "queue_run_interval";
    private static final String REDIS_SERVER_HOST = "redis_server_host";
    private static final String REDIS_SERVER_PORT = "redis_server_port";

    private static final String COUNTRY_CODE = "country_code";
    private static final String NETWORK_CODES = "network_codes";
    private static final String NUMBER_LENGTH = "number_length";
    private static final String DEFAULT_OTA_SPI_1 = "default_ota_spi1";
    private static final String DEFAULT_OTA_SPI_2 = "default_ota_spi2";
    private static final String MAXIMUM_RETRIES = "maximum_retries";
    private static final String MAXIMUM_SMS_RETRIES = "maximum_sms_retries";
    private static final String GEOMETRIC_BACKOFF = "geometric_backoff";
    private static final String RETRY_INTERVAL = "retry_interval";
    private static final String CASCADE_FAIL_TRANSACTIONS = "cascade_fail_transactions";
    private static final String EXPIRED_TRANSACTION_SMS = "expired_transaction_sms";

    private static final String ALWAYS_USE_DLR = "always_use_dlr";
    private static final String SMS_THROUGHPUT = "sms_throughput";
    private static final String USE_SSL = "use_ssl";
    private static final String SENDSMS_URL = "sendsmsUrl";
    private static final String VIRTUAL_SMSC_PORT = "virtual_smsc_port";
    private static final String VIRTUAL_SMSC_NUMBER = "virtual_smsc_number";
    private static final String VIRTUAL_SMSC_NUMBER_PREFIX = "virtual_smsc_number_prefix";
    private static final String VIRTUAL_SMSC_SHORTCODES = "virtual_smsc_shortcodes";
    private static final String SMS_THROUGHPUT1 = "sms_throughput";
    private static final String BIP_APN = "bip_apn";
    private static final String BIP_TITLE = "bip_title";
    private static final String BIP_ME_BUFFER = "bip_me_buffer";
    private static final String BIP_PORT = "bip_port";
    private static final String BIP_NETWORK_INTERFACE = "bip_network_interface";
    private static final String MAX_BIP_SEND_QUEUE = "max_bip_send_queue";
    private static final String MAX_BIP_DATA_FLAG_CACHE_INTERVAL = "max_bip_data_flag_cache_interval";
    private static final String HLR_GATEWAY_COMMAND = "hlr_gateway_command";
    private static final String IMSI_LOOKUP_COMMAND = "imsi_lookup_command";
    private static final String MAX_BIP_SEND_REQUESTS = "max_bip_send_requests";
    private static final String BIP_IDLE_TIMEOUT = "bip_idle_timeout";
    private static final String BIP_PUSH_RETRY_TIMEOUT = "bip_push_retry_timeout";
    private static final String MINIMUM_BIP_TRANSACTIONS = "minimum_bip_transactions";
    private static final String ALLOW_MULTIPLE_SAT_SESSIONS = "allow_multi";
    private static final String RAMHTTP_NUM_RETRIES = "ram_num_retries";
    private static final String RAM_OPEN_CHANNEL_RETRIES = "ram_open_channel_retries";
    private static final String RAMHTTP_ADMIN_PORT = "ram_admin_port";
    private static final String RAM_ADMIN_BACKLOG = "ram_admin_backlog";
    private static final String RAM_ADMIN_HTTP_KEEP_ALIVE_TIMEOUT = "ram_admin_http_keep_alive_timeout";
    private static final String RAM_ADMIN_MAX_HTTP_REQUESTS_PER_SESSION = "ram_admin_max_http_requests_per_session";
    private static final String RAM_RETRY_TIMEOUT = "ram_retry_timeout";
    private static final String RAM_MAX_SEND_REQUESTS = "ram_max_send_requests";
    private static final String RAM_IDLE_TIMEOUT = "ram_idle_timeout";
    private static final String RAM_USE_DEFAULT_CONFIG = "ram_use_default_config";
    private static final String RAM_POLLING_URI = "ram_polling_uri";
    private static final String MAX_EVENTS_HOURS = "max_events_hours";

    private static final String STATS_INTERVALS = "stats_intervals";

    //  certificate and key aliases
    private static final String CI_CERTIFICATE_ALIAS = "ci_cert_alias";
    private static final String SERVER_ECDSA_SECRET_KEY_ALIAS = "private_key-alias";
    private static final String SERVER_ECDSA_CERTIFICATE_ALIAS = "certificate_key-alias";

    private static final String SERVER_OID = "oid";
    private static final String CRL_X509_CONTENT = "ci_crl_content";
    private static final String ADDITIONAL_DISCRETIONARY_DATA_TLVS = "discretionary_data_tlvs";
    private static final String SIGNED_SM_DP_DATA = "signed-sm-dp-data";
    private static final String SIGNED_SM_SR_DATA = "signed-sm-sr-data";
    private static final String WS_PREFIX = "ws-interface-prefix";

    // This stores all the config params, with their validators and current values
    private static final Map<String, BaseValidator> configValidators = new ConcurrentHashMap<String, BaseValidator>() {
        {
            put(MYHOSTNAME, new BaseValidator("localhost"));
            put(MYPORT, new IntegerValuesValidator(8080));
            put(MAXBATCHQSIZE, new IntegerValuesValidator(10));
            put(MAXTHREADS, new IntegerValuesValidator(1));

            put(QUEUERUNINTVL, new RealValuesValidator(10)); // In seconds
            put(REDIS_SERVER_HOST, new BaseValidator("localhost"));
            put(REDIS_SERVER_PORT, new IntegerValuesValidator(6379));


            put(COUNTRY_CODE, new IntegerValuesValidator(86) {
                @Override
                Object value(Object val) throws Exception {
                    super.value(val); // Check it.
                    return val.toString(); // Then return it as a string.

                }
            });

            put(NETWORK_CODES, new StringListValidator(new String[]{"1",}, new IntegerValuesValidator(0)));

            put(NUMBER_LENGTH, new IntegerValuesValidator(12));

            put(DEFAULT_OTA_SPI_1, new IntegerValuesValidator(0x16)); // See Secion 2.4.3 of SGP-02-3-0
            put(DEFAULT_OTA_SPI_2, new IntegerValuesValidator(0x39));

            put(MAXIMUM_RETRIES, new IntegerValuesValidator(10));
            put(MAXIMUM_SMS_RETRIES, new IntegerValuesValidator(10));

            put(GEOMETRIC_BACKOFF, new BooleanValidator(false));


            put(RETRY_INTERVAL, new PositiveIntegerValuesValidator(3 * 60));
            put(CASCADE_FAIL_TRANSACTIONS, new BooleanValidator(false));

            put(EXPIRED_TRANSACTION_SMS, new BaseValidator(null));


            put(ALWAYS_USE_DLR, new BooleanValidator(false));

            put(SMS_THROUGHPUT, new IntegerValuesValidator(10));

            put(USE_SSL, new BooleanValidator(false));

            put(BASEDEPLOYMENTURI, new BaseValidator("/dstk"));

            put(SENDSMS_URL, new BaseValidator("http://localhost:13013/cgi-bin/sendsms?username=tester&password" +
                    "=foobar"));

            put(VIRTUAL_SMSC_PORT, new IntegerValuesValidator(8182));

            put(VIRTUAL_SMSC_NUMBER, new BaseValidator("1000"));
            put(VIRTUAL_SMSC_NUMBER_PREFIX, new BaseValidator("8000"));

            put(VIRTUAL_SMSC_SHORTCODES, new StringListValidator(new String[]{"1000", "+256772865416"},
                    new IntegerValuesValidator(0)));

            put(SMS_THROUGHPUT1, new IntegerValuesValidator(10));

            put(BIP_APN, new ByteArrayValidator("internet") {
                @Override
                protected byte[] getBytes(String value) throws Exception {
                    String[] xl = value.split("[.]");
                    String out = "";
                    ByteArrayOutputStream os = new ByteArrayOutputStream();
                    for (String s : xl)
                        try {
                            os.write(s.length());
                            os.write(s.getBytes(StandardCharsets.UTF_8));
                        } catch (Exception ex) {
                        }
                    return os.toByteArray();
                }
            });
            put(BIP_TITLE, new BaseValidator("Accept"));

            put(BIP_ME_BUFFER, new IntegerValuesValidator(512));
            put(BIP_PORT, new IntegerValuesValidator(2345));

            String ipAddress;
            try {
                InetAddress IP = InetAddress.getLocalHost();
                ipAddress = IP.getHostAddress();
            } catch (Exception ex) {
                ipAddress = "10.211.55.2";
            }
            put(BIP_NETWORK_INTERFACE, new InetInterfaceValidator(ipAddress));
            put(MAX_BIP_SEND_QUEUE, new PositiveIntegerValuesValidator(100));
            put(MAX_BIP_DATA_FLAG_CACHE_INTERVAL, new PositiveIntegerValuesValidator(3600 * 24));
            put(HLR_GATEWAY_COMMAND, new BaseValidator("/usr/local/bin/hlr_gw.sh"));
            put(IMSI_LOOKUP_COMMAND, new BaseValidator("/usr/local/bin/msisdn_map.sh"));

            put(MAX_BIP_SEND_REQUESTS, new PositiveIntegerValuesValidator(10));
            put(BIP_IDLE_TIMEOUT, new PositiveIntegerValuesValidator(120));
            put(BIP_PUSH_RETRY_TIMEOUT, new PositiveIntegerValuesValidator(60 * 4));
            put(MINIMUM_BIP_TRANSACTIONS, new PositiveIntegerValuesValidator(3));
            put(ALLOW_MULTIPLE_SAT_SESSIONS, new BooleanValidator(true));

            put(RAMHTTP_NUM_RETRIES, new PositiveIntegerValuesValidator(10)); // Default is no retries

            put(RAMHTTP_ADMIN_PORT, new PositiveIntegerValuesValidator(9443));
            put(RAM_ADMIN_BACKLOG, new PositiveIntegerValuesValidator(10));
            put(RAM_ADMIN_HTTP_KEEP_ALIVE_TIMEOUT, new PositiveIntegerValuesValidator(120)); // HTTP Connection
            // considered dead after 120 seconds.
            put(RAM_ADMIN_MAX_HTTP_REQUESTS_PER_SESSION, new PositiveIntegerValuesValidator(100));

            put(RAM_RETRY_TIMEOUT, new PositiveIntegerValuesValidator(120));

            put(RAM_MAX_SEND_REQUESTS, new PositiveIntegerValuesValidator(10));

            put(RAM_IDLE_TIMEOUT, new PositiveIntegerValuesValidator(60)); // Idle after 60 seconds.
            put(RAM_USE_DEFAULT_CONFIG, new BooleanValidator(false));
            put(RAM_POLLING_URI, new BaseValidator("polling"));
            put(RAM_OPEN_CHANNEL_RETRIES, new PositiveIntegerValuesValidator(0));
            put(MAX_EVENTS_HOURS, new PositiveIntegerValuesValidator(1));
            put(STATS_INTERVALS, new PositiveIntegerListValidator(new int[]{5, 30, 60, 3600}));
            put(CI_CERTIFICATE_ALIAS, new BaseValidator("ci-certificate"));
            put(CRL_X509_CONTENT, new BaseValidator(""));
            put(SERVER_ECDSA_CERTIFICATE_ALIAS, new BaseValidator("server-ecda-certificate"));
            put(SERVER_ECDSA_SECRET_KEY_ALIAS, new BaseValidator("server-pkey"));
            put(SERVER_OID, new BaseValidator("1.2.3.4"));
            put(ADDITIONAL_DISCRETIONARY_DATA_TLVS, new TLVsValidator(""));
            put(SIGNED_SM_DP_DATA, new ByteArrayValidator("", true));
            put(SIGNED_SM_SR_DATA, new ByteArrayValidator("", true));
            put(WS_PREFIX, new BaseValidator(""));
        }
    };

    private static Map<String, Object> propertyValues = validateProps(null); // Load initial with nothing


    public static int[] getStatsIntervals() {
        return (int[]) propertyValues.get(STATS_INTERVALS);
    }

    public static int getRamOpenChannelRetries() {
        return (Integer) propertyValues.get(RAM_OPEN_CHANNEL_RETRIES);
    }

    public static String getRamPollingUri() {
        return (String) propertyValues.get(RAM_POLLING_URI);
    }

    public static boolean getRamUseDefaultConfig() {
        return (Boolean) propertyValues.get(RAM_USE_DEFAULT_CONFIG);
    }

    public static int getRamPushRetryTimeOut() {
        return (Integer) propertyValues.get(RAM_RETRY_TIMEOUT);
    }

    public static int getRamMaxSendRequests() {
        return (Integer) propertyValues.get(RAM_MAX_SEND_REQUESTS);
    }

    public static int getNumThreads() {
        return (Integer) propertyValues.get(MAXTHREADS);
    }

    public static double getQueuerunintvl() {
        return (Double) propertyValues.get(QUEUERUNINTVL);
    }

    public static String getRedis_server() {
        return (String) propertyValues.get(REDIS_SERVER_HOST);
    }

    public static int getRedis_port() {
        return (Integer) propertyValues.get(REDIS_SERVER_PORT);
    }


    public static String getCountry_code() {
        return (String) propertyValues.get(COUNTRY_CODE);
    }

    public static String[] getNetwork_codes() {
        return (String[]) propertyValues.get(NETWORK_CODES);
    }

    public static int getNumber_length() {
        return (Integer) propertyValues.get(NUMBER_LENGTH);
    }

    public static int getDefault_ota_spi1() {
        return (Integer) propertyValues.get(DEFAULT_OTA_SPI_1);
    }

    public static int getDefault_ota_spi2() {
        return (Integer) propertyValues.get(DEFAULT_OTA_SPI_2);
    }

    public static int getMaxRetries() {
        return (Integer) propertyValues.get(MAXIMUM_RETRIES);
    }

    public static boolean isGeometricBackOff() {
        return (Boolean) propertyValues.get(GEOMETRIC_BACKOFF);
    }

    public static int getRetryInterval() {
        return (Integer) propertyValues.get(RETRY_INTERVAL);
    }

    public static boolean isAlwaysUseDlr() {
        return (Boolean) propertyValues.get(ALWAYS_USE_DLR);
    }

    public static int getSmsThroughput() {
        return (Integer) propertyValues.get(SMS_THROUGHPUT);
    }

    public static String getMyhostname() {
        return (String) propertyValues.get(MYHOSTNAME);
    }

    public static int getMyport() {
        return (Integer) propertyValues.get(MYPORT);
    }

    public static boolean isUseSSL() {
        return (Boolean) propertyValues.get(USE_SSL);
    }

    public static String getDlrUri() {
        // return (String) propertyValues.get(DLR_URI);
        return propertyValues.get(BASEDEPLOYMENTURI) + "/" + Constants.DLR_URI;
    }

    public static String getBasedeploymenturi()
    {
        return (String)propertyValues.get(BASEDEPLOYMENTURI);
    }

    public static String getSendSmsUrl() {
        return (String) propertyValues.get(SENDSMS_URL);
    }

    public static int getVsmscPort() {
        return (Integer) propertyValues.get(VIRTUAL_SMSC_PORT);
    }

    public static String getVsmsc_number() {
        return (String) propertyValues.get(VIRTUAL_SMSC_NUMBER);
    }

    public static String getVsmscnumberPrefix() {
        return (String) propertyValues.get(VIRTUAL_SMSC_NUMBER_PREFIX);
    }

    public static byte[] getBip_apn() {
        return (byte[]) propertyValues.get(BIP_APN);
    }

    public static String getBip_title() {
        return (String) propertyValues.get(BIP_TITLE);
    }

    public static int getBip_me_buffer_size() {
        return (Integer) propertyValues.get(BIP_ME_BUFFER);
    }

    public static int getCat_tp_port() {
        return (Integer) propertyValues.get(BIP_PORT);
    }

    public static byte[] getBip_network_interface() {
        Object xv = propertyValues.get(BIP_NETWORK_INTERFACE);
        return (byte[]) xv;
    }

    public static int getMax_bip_send_queue() {
        return (Integer) propertyValues.get(MAX_BIP_SEND_QUEUE);
    }

    public static long getMax_bip_data_flag_cache_interval() {
        return (Integer) propertyValues.get(MAX_BIP_DATA_FLAG_CACHE_INTERVAL);
    }

    public static String getHlr_gateway_command() {
        return (String) propertyValues.get(HLR_GATEWAY_COMMAND);
    }

    public static int getMax_bip_send_requests() {
        return (Integer) propertyValues.get(MAX_BIP_SEND_REQUESTS);
    }

    public static int getBip_idle_timeout() {
        return (Integer) propertyValues.get(BIP_IDLE_TIMEOUT);
    }

    public static long getBip_push_retry_timeout() {
        return (Integer) propertyValues.get(BIP_PUSH_RETRY_TIMEOUT);
    }

    public static int getScWsNumberOfRetries() {
        return (Integer) propertyValues.get(RAMHTTP_NUM_RETRIES);
    }

    /**
     * @return
     * @brief Get the HTTP TCP Port number
     */
    public static int getRamhttpAdminPort() {
        return (Integer) propertyValues.get(RAMHTTP_ADMIN_PORT);
    }

    /**
     * @return
     * @brief Get the HTTP Port backlog
     */
    public static int getRamAdminBackLog() {
        return (Integer) propertyValues.get(RAM_ADMIN_BACKLOG);
    }

    public static int getMaxEventsHours() {
        return (Integer) propertyValues.get(MAX_EVENTS_HOURS);
    }

    /**
     * @return
     * @brief Get the Keep Alive Timeout
     */
    public static int getRAMAdminHttpKeepAliveTimeOut() {
        return (Integer) propertyValues.get(RAM_ADMIN_HTTP_KEEP_ALIVE_TIMEOUT);
    }

    public static int getRAMAdminHttpMaxRequests() {
        return (Integer) propertyValues.get(RAM_ADMIN_MAX_HTTP_REQUESTS_PER_SESSION);
    }

    public static Utils.Pair<String, X509Certificate> getCiCertAndAlias() throws Exception {
        return getCert(CI_CERTIFICATE_ALIAS);
    }

    public static X509Certificate getCiCert() throws Exception {
        return getCiCertAndAlias().l;
    }

    public static void updateCiCert(EntityManager em, X509Certificate certificate) throws Exception {
        updateCert(em, CI_CERTIFICATE_ALIAS, certificate,true);
    }

    public static Utils.Pair<String, X509Certificate> getServerCertAndAlias() throws Exception {
        return getCert(SERVER_ECDSA_CERTIFICATE_ALIAS);
    }

    public static X509Certificate getServerCert() throws Exception {
        return getServerCertAndAlias().l;
    }

    public static void updateServerCert(EntityManager em, X509Certificate certificate) throws Exception {
        updateCert(em, SERVER_ECDSA_CERTIFICATE_ALIAS, certificate,false);
    }

    private static Utils.Pair<String, X509Certificate> getCert(String propertykey) throws Exception {
        String alias = (String) propertyValues.get(propertykey);

        // Try to load it from keystore

            KeyStore ks = Utils.getKeyStore();
            X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
            if (cert == null)
                throw new Utils.KeyStoreEntryNotFound("Certificate not found");
            return new Utils.Pair<>(alias, cert);
    }


    private static void updateCert(EntityManager em, String propkey, X509Certificate certificate, boolean trusted) throws Exception {
        KeyStore ks = Utils.getKeyStore();
        String alias = (String) propertyValues.get(propkey);
        if (!trusted)
            ks.setCertificateEntry(alias, certificate);
        else {
            KeyStore.TrustedCertificateEntry c = new KeyStore.TrustedCertificateEntry(certificate);
            ks.setEntry(alias,c,null);
        }
        updateProp(em, propkey, alias);
    }

    public static String getServerEcdsaSecretKeyAlias() {
        return (String) propertyValues.get(SERVER_ECDSA_SECRET_KEY_ALIAS);
    }
    public static PrivateKey getServerECDAPrivateKey() {
        String alias = (String) propertyValues.get(SERVER_ECDSA_SECRET_KEY_ALIAS);
        try {
            KeyStore ks = Utils.getKeyStore();
            return (PrivateKey) ks.getKey(alias, null);
        } catch (Exception ex) {
            return null;
        }
    }

    public static void updateServerECDAPrivateKey(EntityManager em, PrivateKey pkey) throws Exception {
        X509Certificate cert = getServerCert();
        updatePrivateKey(em, SERVER_ECDSA_SECRET_KEY_ALIAS, pkey, cert);
    }

    private static void updatePrivateKey(EntityManager em, String propkey, PrivateKey pkey,
                                         X509Certificate certificate) throws Exception {
        KeyStore ks = Utils.getKeyStore();
        String alias = (String) propertyValues.get(propkey);
        Certificate[] chain = new Certificate[]{certificate, getCiCertAndAlias().l};
        ks.setKeyEntry(alias, pkey, null, chain);
    }


    public static String getOid() {
        return (String) propertyValues.get(SERVER_OID);
    }



    public static void updateOid(EntityManager em, String oid) throws Exception {
        String xoid = oid.trim();
        if (!Pattern.matches("^([1-9][0-9]{0,3}|0)([.]([1-9][0-9]{0,6}|0)){5,13}$", xoid))
            throw new Exception("Invalid OID");
        updateProp(em, SERVER_OID, xoid);
    }

    public static void updateBaseURL(EntityManager em, String baseUrl) throws Exception {
        updateProp(em, BASEDEPLOYMENTURI, baseUrl);
    }

    public static X509CRL getCRL() {
        String pem = (String) propertyValues.get(CRL_X509_CONTENT);
        try {
            return Utils.parseCRL(pem.getBytes(StandardCharsets.UTF_8));
        } catch (Exception ex) {
            return null;
        }
    }

    public static void updateCRL(EntityManager em, byte[] crldata) throws Exception {
        X509CRL crl = Utils.parseCRL(crldata); // Will throw exception...
        updateProp(em, CRL_X509_CONTENT,   new String(crldata, StandardCharsets.UTF_8));
    }

    public static byte[] getAdditionalDiscretionaryDataTlvs() {
        return (byte[]) propertyValues.get(ADDITIONAL_DISCRETIONARY_DATA_TLVS);
    }

    public static void updateAdditionalDiscretionaryDataTlvs(EntityManager em, String data) throws Exception {
        Utils.HEX.h2b(data); // So it fails..
        updateProp(em, ADDITIONAL_DISCRETIONARY_DATA_TLVS, data);
    }

    public static byte[] getSMDPSignedData() {
        return (byte[]) propertyValues.get(SIGNED_SM_DP_DATA);
    }

    public static byte[] getSMSRSignedData() {
        return (byte[]) propertyValues.get(SIGNED_SM_SR_DATA);
    }

    public static void updateSMDPSignedData(EntityManager em, String data) throws Exception {
        updateProp(em, SIGNED_SM_DP_DATA, data);
    }

    public static void updateSMSRSignedData(EntityManager em, String data) throws Exception {
        updateProp(em, SIGNED_SM_SR_DATA, data);
    }

    /* Load the system properties from the db */
    public static void loadProps(EntityManager em) {
        Map<String, String> m = ServerConfigurations.load(em);
        propertyValues = validateProps(m);
    }

    public static void updateProp(EntityManager em, String key, String value) throws Exception {

        Object nvalue = updateProp(key, value);
        if (nvalue != null) ServerConfigurations.updateSetting(em, key, nvalue.toString());
        else throw new Exception("Invalid format");

    }

    public static Object updateProp(String key, String value) throws Exception {
        BaseValidator validator = configValidators.get(key);
        Object nvalue = validator.value(value);
        if (nvalue != null) {
            propertyValues.put(key, nvalue);
        } else throw new Exception("Invalid format");
        return value;
    }

    private static Map<String, Object> validateProps(Map<String, String> p) {

        Set<String> keys = p == null ? new HashSet<>() : p.keySet();

        Map<String, Object> vals = new ConcurrentHashMap<>();
        for (Object k : keys)
            try {
                BaseValidator validator = configValidators.get(k);
                Object v = p.get(k);

                Object nvalue = validator.value(v.toString());

                if (nvalue != null) vals.put(k.toString(), nvalue);
            } catch (Exception ex) {
            }

        // Then put in defaults
        Set<String> vkeys = configValidators.keySet();
        for (String k : vkeys)

            if (!keys.contains(k)) try {
                BaseValidator validator = configValidators.get(k);
                Object xvalue = validator.getDefault();
                Object nvalue = validator.value(xvalue);
                if (nvalue != null) vals.put(k, nvalue);
            } catch (Exception ex) {
                Utils.lg.severe(String.format("Properties Load: Error validating [%s]: %s", k, ex));
            }

        return vals;
    }


    /**
     * The basic validator of a configuration parameter.
     */
    private static class BaseValidator {
        /**
         * The default value for a parameter if none is given
         */
        protected Object default_value = null;

        public BaseValidator(Object defaultVal) {
            default_value = defaultVal;
        }

        /**
         * @param val - The value read from the conf file
         * @return - The value, validated and cleaned up
         * @throws Exception - exception is thrown if value is of the wrong type
         */
        Object value(Object val) throws Exception {
            return val;
        }

        /**
         * @return The default value
         * @brief Get the default value, to be used if none was supplied in the configuration file
         */
        final Object getDefault() {
            return default_value;
        }
    }

    /**
     * Validator for Integer property values
     */
    private static class IntegerValuesValidator extends BaseValidator {
        public IntegerValuesValidator(int defaultVal) {
            super(defaultVal);
        }

        @Override
        Object value(Object val) throws Exception {
            if (val instanceof Integer) return val;
            else if (val instanceof String) return Integer.parseInt(val.toString());

            throw new Exception(String.format("Must be a number [default: %s]", default_value != null ?
                    default_value : "n/a"));
        }
    }

    /**
     * Validator for non-negative Integer property values
     */
    private static class PositiveIntegerValuesValidator extends BaseValidator {
        public PositiveIntegerValuesValidator(int defaultVal) {
            super(defaultVal);
        }

        @Override
        Object value(Object val) throws Exception {
            if (val instanceof Integer) return val;
            else if (val instanceof String) {
                int x = Integer.parseInt(val.toString());
                return x < 0 ? default_value : x;
            }
            throw new Exception(String.format("Must be a number [default: %s]", default_value != null ?
                    default_value : "n/a"));
        }
    }

    /**
     * Validator for floating point values
     */
    private static class RealValuesValidator extends BaseValidator {
        public RealValuesValidator(double defaultVal) {
            super(defaultVal);
        }

        @Override
        Object value(Object val) throws Exception {
            if (val instanceof Double) return val;
            else if (val instanceof String) return Double.parseDouble(val.toString());

            throw new Exception(String.format("Must be a number [default: %s]", default_value != null ?
                    default_value : "n/a"));
        }
    }

    /**
     * IP addresses validator
     */
    private static class InetInterfaceValidator extends BaseValidator {
        public InetInterfaceValidator(String address) {
            super(address);
        }

        @Override
        Object value(Object val) throws Exception {
            if (val instanceof String)
                return InetAddress.getByName(val.toString()).getAddress(); // Return as byte array
            else if (val instanceof InetAddress) return ((InetAddress) val).getAddress();

            throw new Exception(String.format("Must be a hostname [default: %s]", default_value != null ?
                    default_value : "n/a"));
        }
    }

    /**
     * Boolean values validator
     */
    private static class BooleanValidator extends BaseValidator {
        public BooleanValidator(boolean value) {
            super(value);
        }

        @Override
        Object value(Object val) throws Exception {
            if (val instanceof Boolean) return val;

            else if (val instanceof String) return Boolean.parseBoolean(val.toString());
            else if (val instanceof Integer) return 0 != (Integer) val;
            throw new Exception(String.format("Must be a boolean value \"true\" or \"false\" [default: %s]",
                    default_value != null ? default_value : "n/a"));
        }
    }

    /**
     * String lists validator
     */
    private static class StringListValidator extends BaseValidator {
        private BaseValidator elementValidator = null;

        public StringListValidator(String[] defaultval, BaseValidator elementValidator) {
            super(defaultval);

            this.elementValidator = elementValidator;
        }

        @Override
        Object value(Object val) throws Exception {
            if (val instanceof String) {
                String[] vals = val.toString().split("[,]");

                if (elementValidator != null) for (String xv : vals)
                    elementValidator.value(xv); // Validate and hope for the best
                return vals;
            } else if (val instanceof String[]) return val;

            throw new Exception(String.format("Must be a  comma-separated list of strings [default: %s]",
                    default_value != null ? default_value : "n/a"));
        }
    }


    /**
     * +ve integer lists validator
     */
    private static class PositiveIntegerListValidator extends BaseValidator {

        public PositiveIntegerListValidator(int[] defaultval) {
            super(defaultval);
        }

        @Override
        Object value(Object val) throws Exception {
            if (val instanceof String) {
                String[] vals = val.toString().split("[,]");
                List<Integer> l = new ArrayList<>();
                for (String xv : vals)
                    try {
                        int x = Integer.parseInt(xv);
                        if (x <= 0) throw new Exception("expected positive integer");
                        l.add(x);
                    } catch (Exception ex) {
                        throw new Exception("Invalid item [" + xv + "] in +ve integer list: " + ex.getMessage());
                    }
                return l.stream().mapToInt(i -> i).toArray();
            } else if (val instanceof int[]) return val;

            throw new Exception(String.format("Must be a  comma-separated list of integers [default: %s]",
                    default_value != null ? default_value : "n/a"));
        }
    }

    /**
     * Byte arrays valiator
     */
    private static class ByteArrayValidator extends BaseValidator {
        protected boolean hexCoded;

        public ByteArrayValidator(String val) {
            super(val);
            hexCoded = false;
        }

        public ByteArrayValidator(String val, boolean hexCoded) {
            super(val);
            this.hexCoded = hexCoded;
        }

        @Override
        Object value(Object val) throws Exception {
            if (val instanceof String) return getBytes(val.toString());

            throw new Exception(String.format("Value must be a string, default: %s", default_value != null ?
                    default_value : "n/a"));
        }

        protected byte[] getBytes(String value) throws Exception {
            return hexCoded ? Utils.HEX.h2b(value) : value.getBytes(StandardCharsets.UTF_8);
        }
    }

    /**
     * TLVs validator
     */
    private static class TLVsValidator extends ByteArrayValidator {
        public TLVsValidator(String val) {
            super(val, true);
        }

        @Override
        Object value(Object val) throws Exception {
            byte[] value = getBytes((String) val);
            if (value == null || value.length == 0) return null;
            Utils.BER.decodeTLVs(value); // So it can fail.
            return value;
        }
    }

    /**
     * @brief These are constants inside the system properties. No change to them, naturally.
     */
    public static class Constants {
        public static final String REST_ENDPOINT = "/rest";
        public static final String DLR_URI = "/dlr"; //!< The DLR partial URL
        public static final String version = "1.0";
        public static final String build = "20190207";
        public static final String release = String.format("v%s (Build %s)", version, build);
        public static final String serverName = String.format("eUICC Remote Subscription Management Server %s",
                release);

        public static final int DEFAULT_VALIDITY = 3600 * 24;

        public static String jcaProvider = BouncyCastleProvider.PROVIDER_NAME;
    }
}
/**
 * @}
 */