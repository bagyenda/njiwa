package io.njiwa.common.rest.types;

import io.njiwa.common.Utils;
import io.njiwa.common.model.RpaEntity;
import io.njiwa.common.rest.auth.Realm;
import org.picketlink.idm.PartitionManager;

import javax.persistence.EntityManager;
import java.security.cert.X509Certificate;

/**
 * @brief represents rps element
 */
public class RpsElement {
    public  Long id;
    public String oid;
    public String dns_name;
    public RpaEntity.Type type;
    public String cert;
    public String inbound_user, inbound_pass;
    public String outbound_user, outbound_pass;

    public String es1, es2, es3, es4, es7;

    public String admin;
    public String admin_pass;

    public BasicSettings.CertificateInfo certificateInfo;

    public static RpsElement fromEntity(RpaEntity rpaEntity)  {
        RpsElement element = new RpsElement();
        element.id = rpaEntity.getId();
        element.admin = rpaEntity.getAdmin_user();
        element.oid = rpaEntity.getOid();
        element.dns_name = rpaEntity.getDns_name();
        element.type = rpaEntity.getType();
        element.inbound_user = rpaEntity.getwSuserid();
       // element.inbound_pass = rpaEntity.getwSpassword();
        element.outbound_user = rpaEntity.getOutgoingWSuserid();
        // element.outbound_pass = rpaEntity.getOutgoingWSpassword();

        element.es1 = rpaEntity.getEs1URL();
        element.es2 = rpaEntity.getEs2URL();
        element.es3 = rpaEntity.getEs3URL();
        element.es4  = rpaEntity.getEs4URL();
        element.es7 = rpaEntity.getEs7URL();

        try {
            String alias = rpaEntity.getSecureMessagingCertificateAlias();
            if (alias != null)
                element.certificateInfo = BasicSettings.CertificateInfo.create(alias);
        } catch (Exception ex) {}
        return element;
    }

    public  RpaEntity toEntity(EntityManager em, PartitionManager partitionManager) throws Exception {
        RpaEntity entity;

        if (id != null)
            entity  = em.find(RpaEntity.class,id);
        else
            entity = new RpaEntity();

        // update stuff
        if (!Utils.isEmpty(oid))
            entity.setOid(oid);
        if (!Utils.isEmpty(dns_name))
            entity.setDns_name(dns_name);
        if (type != null)
            entity.setType(type);
        if (!Utils.isEmpty(inbound_user ))
            entity.setwSuserid(inbound_user);
        if (!Utils.isEmpty(inbound_pass ))
            entity.setwSpassword(inbound_pass);
        entity.setOutgoingAuthMethod(RpaEntity.OutgoingAuthMethod.USER); // For now, only user+pass supported. right?
        if (!Utils.isEmpty(outbound_user ))
            entity.setOutgoingWSuserid(outbound_user);
        if (!Utils.isEmpty(outbound_pass ))
            entity.setOutgoingWSpassword(outbound_pass);
        if (!Utils.isEmpty(es1))
            entity.setEs1URL(es1);
        if (!Utils.isEmpty(es2))
            entity.setEs1URL(es2);
        if (!Utils.isEmpty(es3))
            entity.setEs1URL(es3);
        if (!Utils.isEmpty(es4))
            entity.setEs1URL(es4);
        if (!Utils.isEmpty(es7))
            entity.setEs1URL(es7);

        // Some sanity checks
        if (Utils.isEmpty(entity.getDns_name()))
            throw new RestException("dns_name", "DNS Name must be supplied");
        if (Utils.isEmpty(entity.getOid()))
            throw new RestException("oid", "OID must be supplied");

        // Do certificate
        if (!Utils.isEmpty(cert))
            try {
                String alias = entity.getSecureMessagingCertificateAlias();
                if (Utils.isEmpty(alias)) {
                    alias = entity.makeKeyStoreAlias("ECDSA");
                    entity.setSecureMessagingCertificateAlias(alias);
                }
                X509Certificate certificate =  Utils.certificateFromBytes(Utils.Http.decodeDataUri(cert));
                entity.updateCertInfo(certificate);
                Utils.getKeyStore().setCertificateEntry(alias,certificate); // Save it.
                Utils.writeKeyStore(); // Update to file
            } catch (Exception ex) {
                throw new RestException("cert",ex.getMessage());
            }
        // Do the user: Add it if new.
        if (!Utils.isEmpty(admin) &&
            Utils.isEmpty(entity.getAdmin_user())) {
            if (Utils.isEmpty(admin_pass))
                throw new RestException("admin_pass", "Please specify a password");
            try {
                // If the user doesn't exist, create it.
                String xadmin = String.format("%s@%s", admin, entity.getDns_name());
                // Create picket link realm and so on.
                Realm.addUser(partitionManager, xadmin, admin_pass, true);
                entity.setAdmin_user(xadmin);
            } catch (Exception ex) {
                throw new RestException("admin", ex.getMessage());
            }
        } else if (!Utils.isEmpty(admin_pass))
            try {
                // Update the password
                String xadmin = entity.getAdmin_user();
                Realm.setUserPassword(partitionManager,xadmin,admin_pass);
            } catch (Exception ex) {
                throw new RestException("admin", ex.getMessage());
            }
        if (entity.getId() == null)
            em.persist(entity);
        return entity;
    }
}
