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

package io.njiwa.common.ws;

import io.njiwa.common.model.RpaEntity;
import io.njiwa.common.StatsCollector;
import io.njiwa.common.Utils;
import io.njiwa.common.ws.handlers.AsyncRequestResponse;
import io.njiwa.common.ws.types.WsaEndPointReference;
import io.njiwa.sr.model.AsyncWebServiceResponses;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.persistence.EntityManager;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;
import javax.xml.crypto.*;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.namespace.QName;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPMessage;
import javax.xml.ws.*;
import javax.xml.ws.handler.Handler;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Created by bagyenda on 28/11/2016.
 */
public class WSUtils {

    public final static String REQUESTING_ENTITY_TYPE = WSUtils.class.getCanonicalName() + ".REQUESTING_ENTITY";
    public final static String REQUEST_URI_KEY = WSUtils.class.getCanonicalName() + ".REQUEST_URI";

    public static <T> T getPort(String namespace,
                                String portName, WsaEndPointReference sendTo, Class<T> cls, RpaEntity
                                        .Type ourType, final
                                EntityManager em,
                                Long targetEntity) {
        QName sName = new QName(namespace, portName);
        Service s = Service.create(sName);
        QName pName = new QName(namespace, portName);


        if (sendTo != null)
            s.addPort(pName, "http://schemas.xmlsoap.org/soap/", sendTo.makeAddress());
        T proxy = s.getPort(pName, cls);
        // Record the sender entity ID
        // Record the address
        // Put the handler chain so we can grab and store the response

        BindingProvider provider = (BindingProvider) proxy;
        Binding binding = provider.getBinding();
        Map<String, Object> ctx = provider.getRequestContext();
        try {
            ctx.put(REQUESTING_ENTITY_TYPE, ourType);
            ctx.put(REQUEST_URI_KEY, sendTo.makeAddress());
        } catch (Exception ex) {
        }
        List<Handler> l = new ArrayList<>();
        l.add(new ClientHandler(em, targetEntity));
        binding.setHandlerChain(l);
        return proxy;
    }

    public static HttpServletResponse getRespObject(WebServiceContext context) {
        try {
            MessageContext ctx = context.getMessageContext();
            return (HttpServletResponse) ctx.get(MessageContext.SERVLET_RESPONSE);
        } catch (Exception ex) {
        }
        return null;
    }

    public static class ClientHandler implements SOAPHandler<SOAPMessageContext> {


        public static final String BINARYTOKEN_URI = "#binarytoken";
        public static final String BODY_URI = "#body";
        private EntityManager em;
        private String targetOid;

        public ClientHandler() {
        }

        public ClientHandler(EntityManager em, Long targetEntity) {

            this.em = em;
            try {
                this.targetOid = em.find(RpaEntity.class, targetEntity).getOid();
            } catch (Exception ex) {
            }

        }

        private static void addCertAuth(SOAPEnvelope soapenv)
                throws Exception {
            KeyStore.PrivateKeyEntry pk = Utils.getServerPrivateKey();
            PrivateKey privKey = pk.getPrivateKey();
            X509Certificate certificate = (X509Certificate) pk.getCertificate();

            ByteArrayOutputStream os = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(os);

            oos.writeObject(certificate);
            oos.close();
            Document doc = soapenv.getOwnerDocument();
            String cert = DatatypeConverter.printBase64Binary(os.toByteArray());
            Node header = soapenv.getElementsByTagNameNS("*", "Header").item(0);
            Node body = soapenv.getElementsByTagNameNS("*", "Body").item(0);

            // Find first Element node in the body, and give it the ID. We will sign the body. Right?
            Element respNode = (Element) Utils.XML.findNode(body.getChildNodes(), new Utils.Predicate<Node>() {
                @Override
                public boolean eval(Node obj) {
                    return obj.getNodeType() == Node.ELEMENT_NODE;
                }
            });
            respNode.setAttribute("Id", BODY_URI.substring(1));

            Node secNode = doc.createElementNS("http://docs.oasis-open" +
                    ".org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "Security");
            header.appendChild(secNode);

            Element bNode = doc.createElementNS("http://docs.oasis-open" +
                    ".org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "BinarySecurityToken");
            bNode.setAttribute("id", "binarytoken"); // According to Sec 4 of the WS-Security spec, the plain ID
            // attribute can be used as a reference
            bNode.setAttribute("ValueType", "#X509v3");
            bNode.appendChild(doc.createTextNode(cert));
            secNode.appendChild(bNode);
            XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
            // No need for a de-referencer

            // Create reference to Body
            List<Reference> l = new ArrayList<Reference>();
            Reference ref = fac.newReference(BODY_URI,
                    fac.newDigestMethod(DigestMethod.SHA1, null),
                    Collections.singletonList(fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
                            (C14NMethodParameterSpec) null)),
                    null, null
            );
            l.add(ref);
            ref = fac.newReference(BINARYTOKEN_URI,
                    fac.newDigestMethod(DigestMethod.SHA1, null),
                    Collections.singletonList(fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
                            (C14NMethodParameterSpec) null)),
                    null, null
            );
            l.add(ref);

            SignedInfo si = fac.newSignedInfo(fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
                            (C14NMethodParameterSpec) null),
                    fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
                    l);


            // Keys
            KeyInfoFactory kif = fac.getKeyInfoFactory();

            // Create SecurityTokenReference
            Element st = doc.createElementNS("http://docs.oasis-open" +
                    ".org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "SecurityTokenReference");
            Element stR = doc.createElementNS("http://docs.oasis-open" +
                    ".org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "Reference");
            st.appendChild(stR);
            stR.setAttribute("URI", "#binarytoken");
            DOMStructure dsT = new DOMStructure(st);
            KeyInfo ki = kif.newKeyInfo(Collections.singletonList(dsT));

            // Make signing context
            DOMSignContext dsc = new DOMSignContext(privKey, secNode);

            final Element root = doc.getDocumentElement();
            dsc.setURIDereferencer(new URIDereferencer() {
                @Override
                public Data dereference(URIReference uriReference, XMLCryptoContext context) throws URIReferenceException {
                    String uri = uriReference.getURI();
                    // Look for ID references:

                    String xid = null;
                    if (uri.charAt(0) == '#')
                        xid = uri.substring(1);
                    Node n = xid != null ? Utils.XML.findElementById(root, xid) : null;
                    if (n != null)
                        try {
                            Utils.XML.removeRecursively(n, Node.COMMENT_NODE, null); // Everything but comments
                            String xml = Utils.XML.getNodeString(n);
                            ByteArrayInputStream inputStream = new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8));
                            return new OctetStreamData(inputStream);
                            // return new DOMSubTreeData(n,true);
                        } catch (Exception ex) {
                            return null;
                        }
                    else {
                        URIDereferencer defaultDereferencer = XMLSignatureFactory.getInstance("DOM").
                                getURIDereferencer();
                        return defaultDereferencer.dereference(uriReference, context);
                    }
                }
            });

            // Sign
            XMLSignature sig = fac.newXMLSignature(si, ki);
            sig.sign(dsc);
        }

        @Override
        public Set<QName> getHeaders() {
            return null;
        }

        private void addPwdAuth(SOAPEnvelope soapenv, RpaEntity rpa) throws Exception {
            String nonce = Utils.getRandString();
            Date t = Calendar.getInstance().getTime();
            GregorianCalendar gc = new GregorianCalendar();
            gc.setTime(t);
            String date = DatatypeFactory.newInstance().newXMLGregorianCalendar(gc).toString();
            String userid = rpa.getOutgoingWSuserid();
            String passwd = rpa.getOutgoingWSpassword();
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.update(nonce.getBytes(StandardCharsets.UTF_8));
            md.update(date.getBytes(StandardCharsets.UTF_8));
            md.update(passwd.getBytes(StandardCharsets.UTF_8));
            byte[] out = md.digest();
            String digest = DatatypeConverter.printBase64Binary(out);
            Document doc = soapenv.getOwnerDocument();
            Node header = doc.getElementsByTagNameNS("*", "Header").item(0);

            Node secNode = doc.createElementNS("http://docs.oasis-open" +
                    ".org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "Security");
            header.appendChild(secNode);
            Node utNode = doc.createElementNS("http://docs.oasis-open" +
                    ".org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "UsernameToken");
            secNode.appendChild(utNode);
            Node uNode = doc.createElementNS("http://docs.oasis-open" +
                    ".org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "Username");
            uNode.appendChild(doc.createTextNode(userid));
            utNode.appendChild(uNode);
            Node cNode = doc.createElementNS("http://docs.oasis-open" +
                    ".org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "Created");
            cNode.appendChild(doc.createTextNode(date));

            // Add Password and nonce
            Element pNode = doc.createElementNS("http://docs.oasis-open" +
                    ".org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "Password");
            pNode.setAttribute("Type", "#PasswordDigest");
            pNode.appendChild(doc.createTextNode(digest));
            utNode.appendChild(pNode);
            utNode.appendChild(cNode);
            Element nNode = doc.createElementNS("http://docs.oasis-open" +
                    ".org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "Nonce");
            nNode.appendChild(doc.createTextNode(DatatypeConverter.printBase64Binary(nonce.getBytes(StandardCharsets.UTF_8))));
            utNode.appendChild(nNode);
        }

        @Override
        public boolean handleMessage(SOAPMessageContext context) {
            SOAPMessage message = context.getMessage();

            boolean isOutgoing = (Boolean) context.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
            if (!isOutgoing)
                return true;

            // Get URL and so on
            String url = (String) context.get(REQUEST_URI_KEY);
            RpaEntity rpa;
            try {
                RpaEntity.Type  rtype = (RpaEntity.Type) context.get(REQUESTING_ENTITY_TYPE);
                rpa =  RpaEntity.getLocal(rtype);
            } catch (Exception ex) {
                rpa = null;
            }


            try {
                StatsCollector.recordOtherEntityEvent(targetOid, StatsCollector.EventType.SentPacket);
            } catch (Exception ex) {
            }
            // Now check for the URLs...
            if (url.equalsIgnoreCase(AsyncRequestResponse.ANONYMOUS_URL) ||
                    url.toLowerCase().indexOf(AsyncRequestResponse.ANONYMOUS_URL_TEMPLATE) == 0)
                try {
                    SOAPHeader h = message.getSOAPHeader(); // Get the header

                    // Get WSAction, get body node, save, kill sending request
                    Node aNode = h.getElementsByTagNameNS("*", "Action").item(0);
                    String action = Utils.XML.getNodeValue(aNode);
                    Node body = context.getMessage().getSOAPBody();
                    Node firstChild = Utils.XML.findNode(body.getChildNodes(), new Utils.Predicate<Node>() {
                        @Override
                        public boolean eval(Node obj) {
                            return obj.getNodeType() == Node.ELEMENT_NODE;
                        }
                    });
                    final AsyncWebServiceResponses r = new AsyncWebServiceResponses(rpa, action, firstChild, url.toLowerCase());
                    em.persist(r); // Save it and flush
                    em.flush();

                } catch (Exception ex) {
                    Utils.lg.severe("Failed to process/save async client request: " + ex.getMessage());
                    throw new SuppressClientWSRequest(); // Prevent further processing
                } finally {
                    throw new SuppressClientWSRequest();
                }
            else try {
                SOAPEnvelope env = message.getSOAPPart().getEnvelope();
                RpaEntity.OutgoingAuthMethod method = rpa.getOutgoingAuthMethod();
                if (method == RpaEntity.OutgoingAuthMethod.USER)
                    addPwdAuth(env, rpa);
                else
                    addCertAuth(env);
            } catch (Exception ex) {
                Utils.lg.severe("Error adding auth header to outgoing request: " + ex);
                ex.printStackTrace();
            }
            return true;
        }

        @Override
        public boolean handleFault(SOAPMessageContext context) {

            return true;
        }

        @Override
        public void close(MessageContext context) {

        }
    }

    @WebFault()
    public static class SuppressClientWSRequest extends ProtocolException {
        // Dummy for catching and ignore client sending
        private static final long serialVersionUID = 1L;
        public SuppressClientWSRequest() {

        }

        @Override
        public String getMessage() {
            return "Just killing the connection";
        }
    }

}
