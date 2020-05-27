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

package io.njiwa.common.ws.types;

import io.njiwa.sr.transports.Transport;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import java.util.Date;
import java.util.GregorianCalendar;

/**
 * Created by bagyenda on 04/05/2016.
 */
@XmlRootElement
public class BaseResponseType implements RpsElement {

    @XmlElement(name = "ProcessingStart")
    public
    XMLGregorianCalendar processingStart;

    @XmlElement(name = "ProcessingEnd")
    public
    XMLGregorianCalendar processingEnd;

    @XmlElement(name = "AcceptableValidityPeriod")
    public
    long acceptablevalidity;

    @XmlElement(name = "FunctionExecutionStatus")
    public
    ExecutionStatus functionExecutionStatus;


    public static Transport.MessageStatus toMessageStatus(BaseResponseType r, Transport.MessageStatus defaultStatus)
    {
        return ExecutionStatus.Status.toTransMsgStatus(r  != null ? r.functionExecutionStatus.status : null,
                defaultStatus);
    }
    public BaseResponseType() {

    }

    public BaseResponseType(Date startDate, Date endTime, long acceptablevalidity, ExecutionStatus status) {
        this.acceptablevalidity = acceptablevalidity;

        GregorianCalendar gc = new GregorianCalendar();
        gc.setTime(startDate);
        try {
            this.processingStart = DatatypeFactory.newInstance().newXMLGregorianCalendar(gc);
        } catch (Exception ex) {
        }
        gc.setTime(endTime);
        try {
            this.processingEnd = DatatypeFactory.newInstance().newXMLGregorianCalendar(gc);
        } catch (Exception ex) {
        }
        this.functionExecutionStatus = status;
    }

    /**
     * Created by bagyenda on 18/10/2016.
     */
    @XmlRootElement
    public static class ExecutionStatus {

        @XmlEnum(String.class)
        public enum Status {
            @XmlEnumValue("EXECUTED_SUCCESS")
            ExecutedSuccess,
            @XmlEnumValue("EXECUTED_WITHWARNING")
            ExecutedWithWarning,
            @XmlEnumValue("FAILED")
            Failed,
            @XmlEnumValue("EXPIRED")
            Expired;

            public static Transport.MessageStatus toTransMsgStatus(ExecutionStatus.Status status, Transport
                    .MessageStatus defaultStatus) {
                if (status == null)
                    return defaultStatus;
                switch (status) {
                    case ExecutedSuccess:
                    case ExecutedWithWarning:
                        return Transport.MessageStatus.Sent;
                    case Failed:
                    case Expired:
                    default:
                        return Transport.MessageStatus.SendFailedFatal;
                }
            }
        }

        @XmlRootElement
        public static class StatusCode {
            @XmlElement(name = "Subject")
            public
            String subjectCode;

            @XmlElement(name = "Reason")
            public
            String reasonCode;

            @XmlElement(name = "SubjectIdentifier")
            public
            String subjectIdentifier;

            @XmlElement(name = "Message")
            public
            String message;

            public StatusCode() {
            }

            public StatusCode(String subjectCode, String reasonCode, String subjectIdentifier, String message) {
                this.subjectCode = subjectCode;
                this.reasonCode = reasonCode;
                this.subjectIdentifier = subjectIdentifier;
                this.message = message;
            }
        }

        @XmlElement(name = "Status")
        public
        Status status;

        @XmlElement(name = "StatusCodeData")
        public
        StatusCode statusCodeData;

        public ExecutionStatus() {
        }

        public ExecutionStatus(Status status, StatusCode code) {
            this.status = status;
            this.statusCodeData = code;
        }

        public ExecutionStatus(Status status) {
            this.status = status;
        }
    }
}
