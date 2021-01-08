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

package io.njiwa.sr.transactions;

import io.njiwa.common.ECKeyAgreementEG;
import io.njiwa.common.SDCommand;
import io.njiwa.common.Utils;
import io.njiwa.common.model.*;
import io.njiwa.sr.model.Eis;
import io.njiwa.sr.model.SecurityDomain;
import io.njiwa.sr.model.SmSrTransaction;
import io.njiwa.sr.ota.Ota;

import javax.persistence.EntityManager;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static io.njiwa.common.ECKeyAgreementEG.SGP02_PUBLIC_KEY_TAG;

/**
 * Make a  SCP81 key in the ISDR according to GPC Ammend A&E
 */
public class CreateSCP81KeySet extends SmSrBaseTransaction {

    public int keyVersion;
    public int keyId;

    public byte[] ePk; // The ephemeral keys
    public byte[] eSk;
    public int scenarioParam;
    public int keyParamRef;
    public Certificate.Data ecasdData;

    public byte[] sdin;
    public byte[] sin;
    public byte[] hostId;
    public int eccLength;

    public CreateSCP81KeySet() {
    }

    public CreateSCP81KeySet(Eis eis) throws Exception {
        ecasdData = eis.ecasdKeyAgreementCertificate(); // Get stuff.
        keyParamRef =
                scenarioParam = ECKeyAgreementEG.INCLUDE_DERIVATION_RANDOM;
        KeyPair kp = Utils.ECC.genKeyPair(ecasdData.publicKeyReferenceParam);

        ePk = Utils.ECC.encode((ECPublicKey) kp.getPublic());
        eSk = Utils.ECC.encode((ECPrivateKey) kp.getPrivate());
        Utils.Pair<Integer, Integer> p = KeySet.Type.SCP81.versionLimits();
        keyVersion = p.k; // Take first one.
        keyId = 1; // Set to first one...

        try {
            sdin = Utils.HEX.h2b(eis.findISDR().getSdin());
        } catch (Exception ex) {
            sdin = null;
        }
        try {
            sin = Utils.HEX.h2b(eis.findISDR().getSin());
        } catch (Exception ex) {
            sin = null;
        }
        hostId = new byte[16];
        new SecureRandom().nextBytes(hostId);
        eccLength = Utils.ECC.keyLength((ECPublicKey) kp.getPublic());
        byte[] counter = Utils.encodeInteger(1, 5);
        byte[] a6 = ECKeyAgreementEG.makeA6CRT(1, sdin, hostId, keyId, keyVersion, counter, (byte) 0, KeyComponent
                .Type.PSK_TLS,16, scenarioParam);
        byte[] epkVal = Utils.ECC.encode((ECPublicKey) kp.getPublic(), ecasdData.publicKeyReferenceParam);

        addAPDU(new SDCommand.APDU(0x80, 0xE2, 0x89, 0x01, new ByteArrayOutputStream() {
            {
                write(a6);
                Utils.BER.appendTLV(this, SGP02_PUBLIC_KEY_TAG, epkVal);
            }
        }.toByteArray()));
    }

    // No need to sub-class sendTransaction, only receive
    @Override
    protected synchronized void processResponse(EntityManager em, long tid, TransactionType.ResponseType responseType, String reqId) {
        SmSrTransaction tr = em.find(SmSrTransaction.class, tid);
        Eis eis = tr.eisEntry(em);

        if (responseType == TransactionType.ResponseType.SUCCESS)
            try {
                Ota.ResponseHandler.ETSI102226APDUResponses.Response r = findFirstRAPDU();
                byte[] resp = r.data;
                byte[] dr = null;
                byte[] receipt = null;
                ByteArrayInputStream in = new ByteArrayInputStream(resp);
                while (in.available() > 0) {
                    Utils.Pair<InputStream, Integer> out = Utils.BER.decodeTLV(in);
                    byte[] data = Utils.getBytes(out.k);

                    if (out.l == 0x85)
                        dr = data;
                    else if (out.l == 0x86)
                        receipt = data;
                }

                // Derive receipt ourselves
                byte[] keyData = ECKeyAgreementEG.computeKeyData(ECKeyAgreementEG.KEY_QUAL_ONE_KEY,dr,hostId,sdin,
                        sin,ecasdData.publicKeyQ,keyParamRef,eSk);

                byte[] receiptKey = new byte[16];
                byte[] scp81key = new byte[16];
                System.arraycopy(keyData,0,receiptKey,0,receiptKey.length);
                System.arraycopy(keyData,receiptKey.length,scp81key,0,scp81key.length);
                byte[] cReceipt = ECKeyAgreementEG.computeReceipt(dr,sdin,hostId,keyId,keyVersion,scenarioParam,
                        receiptKey);
                if (!Arrays.equals(cReceipt,receipt))
                    throw new Exception("Mismatch in received receipt, no new SCP81 keys created!");
                // Make new Keys
                SecurityDomain isdr = eis.findISDR();
                KeyComponent kc = new KeyComponent(scp81key, KeyComponent.Type.AES);
                Key key = new Key(keyId,kc);
                KeySet ks = new KeySet(keyVersion, key, KeySet.Type.SCP81,1);
                em.persist(ks);
                List<KeySet> l = isdr.getKeysets();
                if (l == null) {
                    l = new ArrayList<>();
                    isdr.setKeysets(l);
                }
                l.add(ks);
                // Added new key set
            } catch (Exception ex) {
                Utils.lg.severe(String.format("CreateSCP81Keys: Failed to create additional keys: %s ", ex));
            }
        else
            Utils.lg.severe(String.format("CreateSCP81Keys: Failed to create additional keys. "));

    }

}
