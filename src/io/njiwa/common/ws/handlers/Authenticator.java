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

package io.njiwa.common.ws.handlers;

import io.njiwa.common.ServerSettings;
import io.njiwa.common.StatsCollector;
import io.njiwa.common.Utils;
import io.njiwa.common.model.RpaEntity;
import io.njiwa.common.CaseInsensitiveMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.PersistenceContextType;
import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.DatatypeConverter;
import javax.xml.crypto.*;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.namespace.QName;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;
import javax.xml.ws.spi.http.HttpExchange;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * @brief This handles the message authentication/authorisation for the ES* messages
 */
public class Authenticator implements SOAPHandler<SOAPMessageContext> {

    public static final String SMDP_SERVICE_NAME = "SMDP";
    public static final String SMSR_SERVICE_NAME = "SMSR";


    static final long maxNonceAge = 3600 * 6; // Six hours. Right?
    private static final String ENTITY_KEY = Authenticator.class.getCanonicalName() + ".AUTHENTICATED_USER";
    private static final String ACTION_KEY = Authenticator.class.getCanonicalName() + ".WS-Action";
    private static final String ENTITY_AUTH_METHOD = Authenticator.class.getCanonicalName() +
            ".AUTHENTICATION_METHOD";


    //!< When we receive a request, we match it to the type of entity we are authenticating
    private static final Map<String, RpaEntity.Type> interface2RpaType = new CaseInsensitiveMap<RpaEntity.Type>() {{
        put("ES1", RpaEntity.Type.EUM);
        put("ES2", RpaEntity.Type.MNO);
        put("ES3", RpaEntity.Type.SMDP);
        put("ES4", RpaEntity.Type.MNO);
        put("ES7", RpaEntity.Type.SMSR);
    }};
    private static final String RECEIVED_CERT = Authenticator.class.getCanonicalName() + ".RECEIVED_CERT";

    @PersistenceContext(type = PersistenceContextType.TRANSACTION)
    private EntityManager em;

    public static RpaEntity getUser(WebServiceContext context) {
        try {
            MessageContext soapContext = context.getMessageContext();
            return getUser(soapContext);
        } catch (Exception ex) {
        }
        return null;
    }

    public static RpaEntity getUser(MessageContext context) {
        try {
            return (RpaEntity) context.get(ENTITY_KEY);
        } catch (Exception ex) {
        }
        return null;
    }

    public static AuthMethod getAuthMethod(WebServiceContext context) {
        try {
            return (AuthMethod) context.getMessageContext().get(ENTITY_AUTH_METHOD);
        } catch (Exception ex) {
        }
        return null;
    }

    public static String getWSAction(MessageContext context) {
        try {
            return (String) context.get(ACTION_KEY);
        } catch (Exception ex) {
        }
        return null;
    }

    @Override
    public Set<QName> getHeaders() {
        return null;
    }

    /**
     * @param userToken
     * @param type
     * @param em
     * @return
     * @brief Check user/pass
     */
    RpaEntity processUserNode(Node userToken, RpaEntity.Type type, EntityManager em, String uri) throws Exception {
        // Compare in accordance with https://www.oasis-open.org/committees/download.php/13392/wss-v1.1-spec-pr-UsernameTokenProfile-01.htm

        // Get user name
        String user = Utils.XML.getNodeValue(Utils.XML.getNode("Username", userToken.getChildNodes()));
        Node pwdNode = Utils.XML.getNode("Password", userToken.getChildNodes());
        String pwd = Utils.XML.getNodeValue(pwdNode);
        RpaEntity r = type == null ? RpaEntity.getByUserId(em, user) : RpaEntity.getByUserId(em, user, type);
        if (r == null)
            return null;
        String ourPass = r.getwSpassword();
        String pwdType = Utils.XML.getNodeAttr("Type", pwdNode); // Get the type
        if (pwdType == null || pwdType.equalsIgnoreCase("#PasswordText"))
            return ourPass.equals(pwd) ? r : null;
        // Else digest. So: Get Nonce, get Date
        Node nonceNode = Utils.XML.getNode("Nonce", userToken.getChildNodes());
        String created = Utils.XML.getNodeValue(Utils.XML.getNode("Created", userToken.getChildNodes()));
        String nonceEncoding = Utils.XML.getNodeAttr("EncodingType", nonceNode);
        Date currentTime = Calendar.getInstance().getTime();
        Date clientDate = DatatypeConverter.parseDate(created).getTime();
        String nonce = Utils.XML.getNodeValue(nonceNode);
        long dateDiff = (currentTime.getTime() - clientDate.getTime()) / 1000; // Since it is milliseconds
        if (dateDiff < -10 || dateDiff > maxNonceAge) {
            Utils.lg.severe(String.format("Request to [%s],  has old date: theirs [%s], ours [%s]: denied", uri,
                    created, currentTime));
            return null;
        }
        // Now cleanup the nonce: It should be base64 encoded
        MessageDigest md = MessageDigest.getInstance("SHA-1");

        if (nonceEncoding != null && nonceEncoding.toLowerCase().indexOf("hex") >= 0)
            md.update(DatatypeConverter.parseHexBinary(nonce));
        else
            md.update(DatatypeConverter.parseBase64Binary(nonce));
        // Write created
        md.update(created.getBytes(StandardCharsets.UTF_8));
        md.update(ourPass.getBytes(StandardCharsets.UTF_8));

        byte[] out = md.digest();

        byte[] recvHash = DatatypeConverter.parseBase64Binary(pwd);

        // The two must be equal
        return Arrays.equals(out, recvHash) ? r : null;
    }

    @Override
    public boolean handleMessage(SOAPMessageContext context) {
        SOAPMessage message = context.getMessage();
        boolean isOutgoing = (Boolean) context.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);


        if (isOutgoing) {
            RpaEntity entity = (RpaEntity) context.get(ENTITY_KEY);
            try {
                StatsCollector.recordOtherEntityEvent(entity.getOid(), StatsCollector.EventType.SentPacket);
            } catch (Exception ex) {
            }
            return true; // Nothing to do on the outgoing front
        }
        // Check if HTTPS, if not, refuse
        HttpServletRequest req = (HttpServletRequest) context.get(MessageContext.SERVLET_REQUEST);
        final String uri = req.getRequestURI();


        String scheme = req.getScheme();
        if (scheme == null || !scheme.equalsIgnoreCase("https")) {
            Utils.lg.severe(String.format("Request to [%s] without HTTPS, denied", uri));
            return false;
        }

        RpaEntity.Type ourType = RpaEntity.Type.SMSR; // Default. Right?
        final SOAPPart soap = message.getSOAPPart();
        try {
            String[] x = uri.split("/");
            String reqType = x[x.length - 1];
            final RpaEntity.Type eType = interface2RpaType.get(reqType);
            try {
// Get the type of our interface and record incoming packet
                String iType = x[x.length - 2];

                if (iType.equalsIgnoreCase(SMSR_SERVICE_NAME))
                    ourType = RpaEntity.Type.SMSR;
                else
                    ourType = RpaEntity.Type.SMDP;
                StatsCollector.recordOwnEvent(ourType, StatsCollector.EventType.RecvdPacket);
            } catch (Exception ex) {
            }
            SOAPHeader h = message.getSOAPHeader(); // Get the header
            // Get the action header.
            try {
                Node aNode = h.getElementsByTagNameNS("*", "Action").item(0);
                String action = Utils.XML.getNodeValue(aNode);
                context.put(ACTION_KEY, action);
                context.setScope(ACTION_KEY, MessageContext.Scope.APPLICATION);
            } catch (Exception ex) {
            }
            NodeList nl = h.getElementsByTagNameNS("*", "Security");
            if (nl == null || nl.getLength() == 0) {
                Utils.lg.severe(String.format("Request to [%s] denied: No security header", uri));
                return false;
            }
            Node secNode = nl.item(0);
            final Node userNode = Utils.XML.getNode("UsernameToken", secNode.getChildNodes());

            RpaEntity entity = null; // Reset
            AuthMethod authMethod;

            if (userNode != null) {
                authMethod = AuthMethod.PASSWORD;
                entity = processUserNode(userNode, eType, em, uri);
            } else {
                authMethod = AuthMethod.CERTIFICATE;
                // Now check for the Sig node
                Node sigNode = Utils.XML.getNode("Signature", secNode.getChildNodes());
                // Process the signature, if any
                if (sigNode == null) {
                    Utils.lg.severe(String.format("Request to [%s] denied: No signature node", uri));
                    return false;
                }
                try {
                    XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

                    // Get our CI certificate
                    X509Certificate ci_cert;
                    try {
                        ci_cert = ServerSettings.getCiCert();
                    } catch (Exception ex) {
                        ci_cert = null;
                    }
                    if (ci_cert == null) {
                        System.out.println("No CI certificate in storage!");
                        return false;
                    }
                    X509KeySelector keySelector = new X509KeySelector(ci_cert, context);
                    DOMValidateContext validateContext = new DOMValidateContext(keySelector, sigNode);
                    validateContext.setURIDereferencer((URIReference uriReference, XMLCryptoContext ctx)  -> {
                            String xUri = uriReference.getURI();
                            // Look for ID references:
                            String xid = null;
                            if (xUri.charAt(0) == '#')
                                xid = xUri.substring(1);
                            Node n = xid != null ? Utils.XML.findElementById(soap, xid) : null;
                            if (n != null)
                                try {
                                    // return new DOMSubTreeData(n,true);
                                    Utils.XML.removeRecursively(n, Node.COMMENT_NODE, null); // Remove comments
                                    return (NodeSetData) () -> Collections.singletonList(n).iterator();
                                } catch (Exception ex) {
                                    return null;
                                }
                            else {
                                URIDereferencer defaultDereferencer = XMLSignatureFactory.getInstance("DOM").
                                        getURIDereferencer();
                                return defaultDereferencer.dereference(uriReference, ctx);
                            }
                        }
                    );

                    XMLSignature signature = fac.unmarshalXMLSignature(validateContext);

                    boolean cv = signature.validate(validateContext);
                    // Check core validation status.
                    if (cv == false) {
                        Utils.lg.severe("Signature failed core validation");
                        boolean sv = signature.getSignatureValue().validate(validateContext);
                        Utils.lg.severe("signature validation status: " + sv);
                        //if (sv == false) {
                        // Check the validation status of each Reference.
                        Iterator i = signature.getSignedInfo().getReferences().iterator();
                        for (int j = 0; i.hasNext(); j++) {
                            Reference r = (Reference) i.next();
                            boolean refValid = r.validate(validateContext);
                            String xuri = r.getURI();
                            Utils.lg.severe("ref [" + xuri + "] validity status: " + refValid);
                        }
                        return false;
                    } else {
                        Utils.lg.info("Signature passed core validation");

                        // Check that we have/know the certificate
                        X509Certificate recvdCert = (X509Certificate) context.get(RECEIVED_CERT);
                        final String alias = Utils.getKeyStore().getCertificateAlias(recvdCert);
                        // Now look for it by alias
                        entity = RpaEntity.getEntityByWSKeyAlias(em, alias, eType);
                    }
                } catch (Exception ex) {
                    Utils.lg.severe("Failed to validate auth: " + ex.getMessage());
                }
            }

            if (entity == null) {
                try {
                    StatsCollector.recordOwnEvent(ourType, StatsCollector.EventType.AuthError); // Record
                    // auth error
                } catch (Exception ex) {
                }
                return false;
            }

            // Check Denied/Allowed IPs
            try {
                final String HTTP_EXCHANGE_KEY_V21 = "com.sun.xml.ws.http.exchange";
                final String HTTP_EXCHANGE_KEY_V22 = "com.sun.xml.internal.ws.http.exchange";
                // Get source IP
                HttpExchange http = (HttpExchange) context.get(HTTP_EXCHANGE_KEY_V21);
                if (http == null)
                     http = (HttpExchange) context.get(HTTP_EXCHANGE_KEY_V22);
                InetSocketAddress remoteAddress = http.getRemoteAddress();
                String ip = remoteAddress.getAddress().toString();
                if (!entity.isAllowedIP(ip)) {
                    Utils.lg.severe("Denied SOAP Request from  [" + entity.toString() + "] with IP [" + ip + "], " +
                            "denied by allow/deny settings!");
                    StatsCollector.recordOtherEntityEvent(entity.getOid(), StatsCollector.EventType.IPError);
                    return false; // Do not proceed
                }
            } catch (Exception ex) {
            }

            h.removeChild(secNode); // Remove it. Right?
            context.put(ENTITY_AUTH_METHOD, authMethod);
            context.put(ENTITY_KEY, entity);
            context.setScope(ENTITY_AUTH_METHOD, MessageContext.Scope.APPLICATION);
            context.setScope(ENTITY_KEY, MessageContext.Scope.APPLICATION);

            // Record received packet from the entity
            try {
                StatsCollector.recordOtherEntityEvent(entity.getOid(), StatsCollector.EventType.RecvdPacket);
            } catch (Exception ex) {
            }
            return true;
        } catch (Exception ex) {
            Utils.lg.severe(String.format("Request to [%s] denied: %s", uri, ex));
            return false;
        }

    }

    @Override
    public boolean handleFault(SOAPMessageContext context) {
        return false;
    }

    @Override
    public void close(MessageContext context) {

    }

    public enum AuthMethod {CERTIFICATE, PASSWORD}

    /**
     * @brief according to: http://docs.oasis-open.org/wss-m/wss/v1.1.1/os/wss-x509TokenProfile-v1.1.1-os.html the
     * key reference is in a Reference node contained within a SecurityTokenReference node within the KeyInfo
     * structure. It then references a BinarySecurityToken node in the XML, that has the same ID. So, here we go!
     */
    public class X509KeySelector extends KeySelector {
        private X509Certificate parent_cert;
        private SOAPMessageContext msgContext;

        public X509KeySelector(X509Certificate ci_cert, SOAPMessageContext context) {
            parent_cert = ci_cert;

            this.msgContext = context;
        }

        public KeySelectorResult select(KeyInfo keyInfo,
                                        KeySelector.Purpose purpose,
                                        AlgorithmMethod method,
                                        XMLCryptoContext context)
                throws KeySelectorException {
            // KeyInfo must exist. So...

            Iterator ki = keyInfo.getContent().iterator();
            while (ki.hasNext()) {
                DOMStructure info = (DOMStructure) ki.next();
                Node node = info.getNode();
                if (!node.getNodeName().equalsIgnoreCase("SecurityTokenReference"))
                    continue;
                // Look for Reference
                Node refNode = Utils.XML.getNode("Reference", node.getChildNodes());
                if (refNode == null)
                    continue;
                // Get attribute
                String ref = Utils.XML.getNodeAttr("URI", refNode);
                NodeList blist = refNode.getOwnerDocument().getElementsByTagName("BinarySecurityToken");
                if (blist == null)
                    continue;
                // Look for the tag and so forth
                Node bNode = null;
                if (ref.length() > 0 && ref.charAt(0) == '#')
                    ref = ref.substring(1);
                for (int i = 0; i < blist.getLength(); i++) {
                    Node n = blist.item(i);
                    String xId = Utils.XML.getNodeAttr("Id", n);
                    String xType = Utils.XML.getNodeAttr("ValueType", n);
                    if (xId != null && xId.equals(ref) && xType != null && xType.equalsIgnoreCase("#X509v3")) {
                        bNode = n;
                        break;
                    }
                }
                if (bNode == null)
                    continue;
                // Assume content is base64 as per spec
                byte[] data = DatatypeConverter.parseBase64Binary(Utils.XML.getNodeValue(bNode));
                // de-serialise certificate
                try {
                    ObjectInputStream ois = new ObjectInputStream(new BufferedInputStream(new ByteArrayInputStream(data)));
                    X509Certificate certificate = (X509Certificate) ois.readObject();
                    try {
                        certificate.verify(parent_cert.getPublicKey());
                    } catch (Exception ex) {
                        System.out.println(String.format("Invalid certificate chain, does not match our CI: %s", ex));
                        continue;
                    }

                    final PublicKey key = certificate.getPublicKey();
                    // Make sure the algorithm is compatible
                    // with the method.
                    if (algEquals(method.getAlgorithm(), key.getAlgorithm())) {
                        msgContext.put(RECEIVED_CERT, certificate); // Store it. We need it later for look up in the
                        msgContext.setScope(RECEIVED_CERT, MessageContext.Scope.APPLICATION);
                        // DB/Keystore
                        // certificate
                        return () -> key;
                    }
                } catch (Exception ex) {
                    Utils.lg.severe("Failed to find key: " + ex);
                }
            }
            throw new KeySelectorException("No key found!");
        }

        private boolean algEquals(String algURI, String algName) {
            try {
                // Parse the uri
                URL u = new URL(algURI);
                String ref = u.getRef();
                if (ref != null && algName != null &&
                        ref.indexOf(algName.toLowerCase()) == 0)
                    return true;
            } catch (Exception ex) {
                return false;
            }
            return false;
        }
    }
}
