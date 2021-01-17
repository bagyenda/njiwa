package io.njiwa.common.rest;

import io.njiwa.common.ECKeyAgreementEG;
import io.njiwa.common.PersistenceUtility;
import io.njiwa.common.ServerSettings;
import io.njiwa.common.Utils;
import io.njiwa.common.model.RpaEntity;
import io.njiwa.common.rest.annotations.RestRoles;
import io.njiwa.common.rest.auth.UserData;
import io.njiwa.common.rest.types.BasicSettings;
import io.njiwa.common.rest.types.RestResponse;
import io.njiwa.common.rest.types.Roles;

import javax.inject.Inject;
import javax.persistence.EntityManager;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

@Path("/settings")
public class Settings {

    @Inject
    PersistenceUtility po;

    @Inject
    private UserData userData;

    /**
     * @param signedData
     * @param certType
     * @return
     * @throws Exception
     * @brief validates signature and returns it in plain format...
     */
    private static byte[] validateSignedDataAndEncodePlain(byte[] signedData, int certType) throws Exception {
        X509Certificate ciCert, certificate;
        byte[] additionalTLVs;

        try {
            ciCert = ServerSettings.getCiCertAndAlias().l;
        } catch (Exception ex) {
            throw new Exception("CI " + ex.getLocalizedMessage());
        }

        try {
            certificate = ServerSettings.getServerCert();
        } catch (Exception ex) {
            throw new Exception("Server " + ex.getLocalizedMessage());
        }

        try {
            additionalTLVs = Utils.HEX.h2b(ServerSettings.getAdditionalDiscretionaryDataTlvs());
        } catch (Exception ex) {
            additionalTLVs = null;
        }

        // Make signing data.
        byte[] signingData = ECKeyAgreementEG.makeCertSigningData(certificate, certType, additionalTLVs,
                ECKeyAgreementEG.KEY_AGREEMENT_USAGE);
        // Verify signature
        boolean result = Utils.ECC.Signature.verify(ciCert, signedData, signingData);
        if (!result) throw new Exception("Invalid signature!");

        return new Utils.ECC.Signature(signedData,true).encodePlain(ciCert);
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/get")
    @RestRoles({Roles.SystemAdminUser})
    public BasicSettings get() {
        return BasicSettings.get();
    }

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/validatecert")
    @RestRoles({Roles.ALLOWALL})
    public Response validateCert(String certData) {

        try {
            byte[] input = Utils.Http.decodeDataUri(certData);
            BasicSettings.CertificateInfo certificateInfo = BasicSettings.CertificateInfo.create(input);
            return Response.ok(certificateInfo).build();
        } catch (Exception ex) {
            return Response.status(Response.Status.BAD_REQUEST).entity(new RestResponse(RestResponse.Status.Failed,
                    ex.getLocalizedMessage())).build();
        }
    }

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/validatecrl")
    @RestRoles({Roles.ALLOWALL})
    public Response validateCrl(String crl) {
        try {
            BasicSettings.CRLInfo c = BasicSettings.CRLInfo.create(Utils.Http.decodeDataUri(crl));
            return Response.ok(c).build();
        } catch (Exception ex) {
            return Response.status(Response.Status.BAD_REQUEST).entity(new RestResponse(RestResponse.Status.Failed,
                    ex.getLocalizedMessage())).build();
        }
    }

    @GET
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    @Path("/getSigningData")
    public Response getsigningData(@QueryParam("type") String type) {
        // Return signing data
        byte[] additionalTlvs;
        X509Certificate serverCert;
        try {
            serverCert = ServerSettings.getServerCert();
            additionalTlvs = ServerSettings.getAdditionalDiscretionaryDataTlvs();
        } catch (Exception ex) {
            return Response.status(Response.Status.BAD_REQUEST).entity(new RestResponse(RestResponse.Status.Failed,
                    ex.getLocalizedMessage())).build();
        }
        try {
            int certType = type != null && type.toLowerCase().contains("sr") ?
                    ECKeyAgreementEG.SM_SR_CERTIFICATE_TYPE : ECKeyAgreementEG.SM_DP_CERTIFICATE_TYPE;
            byte[] resp = ECKeyAgreementEG.makeCertSigningData(serverCert, certType, additionalTlvs,
                    ECKeyAgreementEG.KEY_AGREEMENT_USAGE);
            String fnameid = type != null && type.toLowerCase().contains("sr") ? "sr" : "dp";
            return Response.ok(resp, MediaType.APPLICATION_OCTET_STREAM).header("Content-Disposition", "attachment; " +
                    "filename=\"sm-" + fnameid + "-signing-data.data\"").build();
        } catch (Exception ex) {
            return Response.status(Response.Status.BAD_REQUEST).entity(new RestResponse(RestResponse.Status.Failed,
                    ex.getLocalizedMessage())).build();
        }
    }

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("/update")
    @RestRoles({Roles.SystemAdminUser})
    public Object save(final BasicSettings settings) {
        // Load stuff in order:
        // - ci Cert,  crl, our server cet, our server key, signed data..
        Object res = po.doTransaction((PersistenceUtility po, EntityManager em) -> {
            if (settings.sm_sr_oid != null) try {
                ServerSettings.updateOid(em, RpaEntity.Type.SMSR, settings.sm_sr_oid);
            } catch (Exception ex) {
                return Response.status(Response.Status.BAD_REQUEST).entity(new RestResponse(RestResponse.Status.Failed, ex.getLocalizedMessage(), "sm_sr_oid")).build();
            }

            if (settings.ci_oid != null) try {
                ServerSettings.updateOid(em, RpaEntity.Type.CI, settings.ci_oid);
            } catch (Exception ex) {
                return Response.status(Response.Status.BAD_REQUEST).entity(new RestResponse(RestResponse.Status.Failed, ex.getLocalizedMessage(), "ci_oid")).build();
            }
            if (settings.ca_id != null)
                try {
                   ServerSettings.updateCAID(em,settings.ca_id);
                }catch (Exception ex) {
                    return Response.status(Response.Status.BAD_REQUEST).entity(new RestResponse(RestResponse.Status.Failed, ex.getLocalizedMessage(), "ca_id")).build();
                }
            if (settings.sm_dp_oid != null) try {
                ServerSettings.updateOid(em, RpaEntity.Type.SMDP, settings.sm_dp_oid);
            } catch (Exception ex) {
                return Response.status(Response.Status.BAD_REQUEST).entity(new RestResponse(RestResponse.Status.Failed, ex.getLocalizedMessage(), "sm_sr_oid")).build();
            }

            if (settings.wsUrlPrefix != null) try {
                ServerSettings.updateBaseURL(em, settings.wsUrlPrefix);
            } catch (Exception ex) {
                return Response.status(Response.Status.BAD_REQUEST).entity(new RestResponse(RestResponse.Status.Failed, ex.getLocalizedMessage(), "wsUrlPrefix")).build();
            }

            if (settings.ciCertificate != null) {
                X509Certificate ciCert;
                try {
                    ciCert = Utils.certificateFromBytes(Utils.Http.decodeDataUri(settings.ciCertificate));
                } catch (Exception ex) {
                    return Response.status(Response.Status.BAD_REQUEST).entity(new RestResponse(RestResponse.Status.Failed, ex.getLocalizedMessage(), "ciCertificate")).build();
                }
                try {
                    ServerSettings.updateCiCert(em, ciCert);
                } catch (Exception ex) {
                    return Response.status(Response.Status.BAD_REQUEST).entity(new RestResponse(RestResponse.Status.Failed, ex.getLocalizedMessage(), "ciCertificate")).build();
                }
            }

            if (settings.crl != null) try {
                ServerSettings.updateCRL(em, Utils.Http.decodeDataUri(settings.crl));
            } catch (Exception ex) {
                return Response.status(Response.Status.BAD_REQUEST).entity(new RestResponse(RestResponse.Status.Failed, ex.getLocalizedMessage(), "crl")).build();

            }
            if (settings.serverCertificate != null) {
                X509Certificate cert;
                // Read and validate it.
                try {
                    cert = Utils.certificateFromBytes(Utils.Http.decodeDataUri(settings.serverCertificate));
                    Utils.checkCertificateTrust(cert);
                } catch (Exception ex) {
                    return Response.status(Response.Status.BAD_REQUEST).entity(new RestResponse(RestResponse.Status.Failed, ex.getLocalizedMessage(), "serverCertificate")).build();
                }
                try {

                    ServerSettings.updateServerCert(em, cert);

                } catch (Exception ex) {
                    return Response.status(Response.Status.BAD_REQUEST).entity(new RestResponse(RestResponse.Status.Failed, ex.getLocalizedMessage(), "serverCertificate")).build();
                }
            }

            if (settings.serverPrivateKey != null) {
                PrivateKey key = null;
                X509Certificate cert;
                byte[] bytes;

                try {
                    bytes = Utils.Http.decodeDataUri(settings.serverPrivateKey);
                    // First get the certificate, then use the public key params therein to load the skey
                    cert = ServerSettings.getServerCert();
                } catch (Exception ex) {
                    return Response.status(Response.Status.BAD_REQUEST).entity(new RestResponse(RestResponse.Status.Failed, ex.getLocalizedMessage(), "serverPrivateKey")).build();
                }
                try {
                    byte[] input = Utils.HEX.h2b(bytes);
                    key = Utils.ECC.decodePrivateKey(input, cert);
                } catch (Exception ex) {
                }
                // If we failed, try loading it from PEM-format
                if (key == null) try {
                    key = (PrivateKey) Utils.keyFromFile(bytes);
                } catch (Exception ex) {
                }
                if (key == null)
                    return Response.status(Response.Status.BAD_REQUEST).entity(new RestResponse(RestResponse.Status.Failed, "Failed to parse key. Please provide a PEM-encoded EC private key or a hex-coded key", "serverPrivateKey")).build();
                try {

                    ServerSettings.updateServerECDAPrivateKey(em, key);
                } catch (Exception ex) {
                    return Response.status(Response.Status.BAD_REQUEST).entity(new RestResponse(RestResponse.Status.Failed, ex.getLocalizedMessage(), "serverPrivateKey")).build();
                }
            }

            // Try and validate signed data
            if (settings.smdpSignedData != null) try {
                byte[] data = Utils.Http.decodeDataUri(settings.smdpSignedData);
                byte[] plainSig = validateSignedDataAndEncodePlain(data, ECKeyAgreementEG.SM_DP_CERTIFICATE_TYPE);

                ServerSettings.updateSMDPSignedData(em, Utils.HEX.b2H(plainSig));

            } catch (Exception ex) {
                return Response.status(Response.Status.BAD_REQUEST).entity(new RestResponse(RestResponse.Status.Failed, ex.getLocalizedMessage(), "smdpSignedData")).build();
            }

            if (settings.smsrSignedData != null) try {
                byte[] data = Utils.Http.decodeDataUri(settings.smsrSignedData);
                byte[] plainSig = validateSignedDataAndEncodePlain(data, ECKeyAgreementEG.SM_SR_CERTIFICATE_TYPE);

                ServerSettings.updateSMSRSignedData(em, Utils.HEX.b2H(plainSig));

            } catch (Exception ex) {
                return Response.status(Response.Status.BAD_REQUEST).entity(new RestResponse(RestResponse.Status.Failed, ex.getLocalizedMessage(), "smsrSignedData")).build();
            }
            return null;
        });
        if (res != null) return res;
        Utils.writeKeyStore(); // Update store to file
        try {
            // Reload it.
            return BasicSettings.get(); // And return it as is.
        } catch (Exception ex) {
            return Response.status(Response.Status.BAD_REQUEST).entity(new RestResponse(RestResponse.Status.Failed,
                    ex.getLocalizedMessage())).build();
        }
    }
}
