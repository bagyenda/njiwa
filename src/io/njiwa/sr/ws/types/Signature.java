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

package io.njiwa.sr.ws.types;

import javax.xml.bind.annotation.XmlAnyElement;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.util.List;

/**
 * Created by bagyenda on 06/05/2016.
 */
@XmlRootElement(namespace = "http://www.w3.org/2000/09/xmldsig#", name="EumSignature")
public class Signature {
    @XmlElement(name = "SignedInfo", namespace = "http://www.w3.org/2000/09/xmldsig#")
    public SignedInfo signedInfo;

    @XmlElement(name = "SignatureValue", namespace = "http://www.w3.org/2000/09/xmldsig#")
    public byte[] signature;

    @XmlElement(name = "KeyInfo", namespace = "http://www.w3.org/2000/09/xmldsig#")
    public KeyInfo keyInfo;

    @XmlRootElement(namespace = "http://www.w3.org/2000/09/xmldsig#")
    public static class KeyInfo {
        @XmlElement(name = "X509Data", namespace = "http://www.w3.org/2000/09/xmldsig#")
        public KeyInfo.X509Data x509Data;

        @XmlRootElement(namespace = "http://www.w3.org/2000/09/xmldsig#")
        public static class X509Data {
            // Either one is given
            @XmlElement(name = "X509SubjectName", namespace = "http://www.w3.org/2000/09/xmldsig#")
            public String subjectName;

            @XmlElement(name="X509SKI", namespace = "http://www.w3.org/2000/09/xmldsig#")
            public String ski;

            @XmlElement(name = "X509Certificate", namespace = "http://www.w3.org/2000/09/xmldsig#")
            public byte[] certificate;
        }
    }

    @XmlRootElement(namespace = "http://www.w3.org/2000/09/xmldsig#")
    public static class SignedInfo {

        @XmlElement(name = "CanonicalizationMethod", namespace = "http://www.w3.org/2000/09/xmldsig#")
        public SignedInfo.AlgoMethod canonicalizationMethod;

        @XmlElement(name = "SignatureMethod", namespace = "http://www.w3.org/2000/09/xmldsig#")
        public SignedInfo.AlgoMethod signatureMethod;

        @XmlElement(name = "Reference", namespace = "http://www.w3.org/2000/09/xmldsig#")
        public SignedInfo.Reference ref;


        @XmlRootElement(namespace = "http://www.w3.org/2000/09/xmldsig#")
        public static class AlgoMethod {
            @XmlAttribute(name = "Algorithm")
            public String algorithm;
        }

        @XmlRootElement(namespace = "http://www.w3.org/2000/09/xmldsig#")
        public static class Transforms {
            @XmlAnyElement
            public List<SignedInfo.Transforms.Transform> transforms;

            @XmlRootElement(namespace = "http://www.w3.org/2000/09/xmldsig#")
            public static class Transform extends SignedInfo.AlgoMethod {
            } // Nothing changed
        }

        @XmlRootElement(namespace = "http://www.w3.org/2000/09/xmldsig#")
        public static class Reference {
            @XmlAttribute(name = "uri")
            public String uri;

            @XmlElement(name = "Transforms", namespace = "http://www.w3.org/2000/09/xmldsig#")
            public SignedInfo.Transforms transforms;

            @XmlElement(name = "DigestValue", namespace = "http://www.w3.org/2000/09/xmldsig#")
            public byte[] digestValue;
            @XmlElement(name = "DigestMethod", namespace = "http://www.w3.org/2000/09/xmldsig#")
            SignedInfo.AlgoMethod digestMethod;

        }

    }
}
