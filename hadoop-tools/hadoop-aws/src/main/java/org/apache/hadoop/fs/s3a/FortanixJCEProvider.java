package org.apache.hadoop.fs.s3a;

import com.fortanix.sdkms.jce.provider.SdkmsJCE;
import com.fortanix.sdkms.jce.provider.service.SdkmsKeyService;
import com.fortanix.sdkms.v1.model.KeyObject;
import com.fortanix.sdkms.v1.model.ObjectType;
import com.fortanix.sdkms.v1.model.SobjectDescriptor;

import com.amazonaws.services.cloudfront.model.InvalidArgumentException;
import com.amazonaws.services.s3.model.EncryptionMaterials;
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider;

import com.google.common.base.Strings;

import org.apache.hadoop.conf.Configuration;
import org.slf4j.Logger;

import java.lang.NullPointerException;

import java.security.*;
import java.security.Provider;
import java.security.ProviderException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.SecretKey;

import java.util.HashMap;
import java.util.Map;

public class FortanixJCEProvider implements EncryptionMaterialsProvider {

    protected static final Logger LOG = S3AFileSystem.LOG;

    private final String ENDPOINT_DEFAULT = "https://sdkms.fortanix.com";
    private final String FXAPIKEY_DEFAULT = "OWFhM2QxYzYtM2NiYS00NDRiLWIwNWEtM2I5YmU1ZjEyZGNjOlNRUFJvU2pnNkxDQmtPanJMbnMtclE=";
    private final String ENDPOINT_CONF = "fs.s3a.cse.fortanixEndpoint";
    private final String APIKEY_CONF = "fs.s3a.cse.fortanixApiKey";

    private final String CSE_MATERIAL_DESC = "jce_fortanix_key"; // S3 object metadata key reference
    private final String KEY_ID = "fortanix_key_id";

    private static SdkmsJCE providerJCE;

    private Configuration conf;
    private Map<String, EncryptionMaterials> materialsCache;
    private String keyName;


    public FortanixJCEProvider(String keyName) {
        // BasicConfigurator.configure();
        LOG.debug("Constructihg.. " + FortanixJCEProvider.class.getName());
        init(keyName);
    }

    public Provider getProviderInstance() {
        return this.providerJCE.getInstance(); //needed for .withCryptoProvider, but NOT USED.
    }

    // TBD JWT Auth
    private void init(String keyName) {
        try {
            String strEndpoint = new String(ENDPOINT_DEFAULT);
            String strApiKey = new String("");
            LOG.debug("init Client..");

            if (conf != null && !Strings.isNullOrEmpty(conf.get(ENDPOINT_CONF))) {
                strEndpoint = conf.get(ENDPOINT_CONF);
            }
            if (conf != null && !Strings.isNullOrEmpty(conf.get(APIKEY_CONF))) {
                strApiKey = conf.get(APIKEY_CONF);
            } else {
                strApiKey = FXAPIKEY_DEFAULT;
            }
            LOG.debug("Trying to login with: " + strEndpoint);
            providerJCE = SdkmsJCE.initialize(strEndpoint, strApiKey); // explicit
            LOG.debug("Successful login");

            if (Security.getProvider(providerJCE.getName()) == null) {
               Security.insertProviderAt(providerJCE, 5);
            }

            this.keyName = keyName;
            this.materialsCache = new HashMap<String, EncryptionMaterials>();
        } catch (ProviderException | NullPointerException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    private String getKeyByName(String keyName) {
        LOG.debug("Getting key by name: " + keyName);
        SobjectDescriptor descriptor = new SobjectDescriptor();
        descriptor.setName(keyName);
        return getKeyInner(descriptor);
    }

    private String getKeyById(String keyId) {
        LOG.debug("Getting key by ID: " + keyId);
        SobjectDescriptor descriptor = new SobjectDescriptor();
        descriptor.setKid(keyId);
        return getKeyInner(descriptor);
    }

    private String getKeyInner(SobjectDescriptor descriptor) {
        try {
            /*
            RSACipher in Fortanix gets called by AWS SDK using WRAP/UNWRAP with a CompositeCEK which is a non-AES key
            special handling needed in SdkmsJCE to treat this cipher in ENCRYPT/DECRYPT mode - TBD @Jeffrey/@Bushra
            Or else a fix will be needed in the AWS SDK to Cipher.init and doFinal using ENCRYPT/DECRYPT mode

            For now lets use AES/GCM for Key Wrap
            also set ENV in Hadoop ENV files so AES:transient keys are EXPORTable by default
            */

            KeyObject ftxKey = SdkmsKeyService.getKeyObject(descriptor);
            String kid = ftxKey.getKid();
            ObjectType keyType = ftxKey.getObjType();
            EncryptionMaterials materials = null;
            if (keyType == ObjectType.RSA) {
                LOG.debug("Getting RSA keys from DSM through JCE SdkmsKeyService");
                Key rsaPrivateKey = SdkmsKeyService.getKeyFromKeyObject(ftxKey, false); // directly get RSA Private Key
                Key rsaPublicKey = SdkmsKeyService.getKeyFromKeyObject(ftxKey, true);

                PrivateKey privateKey = (PrivateKey) rsaPrivateKey;
                PublicKey publicKey = (PublicKey) rsaPublicKey;

                materials = new EncryptionMaterials(new KeyPair(publicKey, privateKey));

            } else if (keyType == ObjectType.AES) {
                LOG.debug("Getting AES key from DSM through JCE SdkmsKeyService");
                SecretKey aesSecretKey = (SecretKey)SdkmsKeyService.getKeyFromKeyObject(ftxKey, false); // directly get AES Secret Key
                materials = new EncryptionMaterials(aesSecretKey);
            } else {
                throw new InvalidKeyException("FortanixJCEProvider was given key " + keyName + " that is not RSA nor AES");
            }

            materials.addDescription(KEY_ID, kid);
            materials.addDescription(CSE_MATERIAL_DESC, keyName);
            this.materialsCache.put(kid, materials);
            return kid;
        } catch (ProviderException | InvalidKeyException | NullPointerException e) {
            throw new RuntimeException(e);
        }
    }

    public String convertWithIteration(Map<String, ?> map) {
        StringBuilder mapAsString = new StringBuilder("{");
        for (String key : map.keySet()) {
            mapAsString.append(key + "=" + map.get(key) + ", ");
        }
        mapAsString.delete(mapAsString.length()-2, mapAsString.length()).append("}");
        return mapAsString.toString();
    }

    @Override
    public EncryptionMaterials getEncryptionMaterials(Map<String, String> materialsDescription) {
        if (materialsDescription != null) {
            String kid = materialsDescription.get(KEY_ID);
            if (kid != null) {
                EncryptionMaterials materials = this.materialsCache.get(kid);
                if (materials != null) {
                    return materials;
                } else {
                    this.getKeyById(kid);
                    return this.materialsCache.get(kid);
                }
            } else {
                throw new RuntimeException("materialsDescription map did not contain '" + KEY_ID + "' key");
            }
        } else {
            throw new InvalidArgumentException("No 'materialsDescription' was provided");
        }
    }

    /**
     * Returns EncryptionMaterials which the caller can use for encryption.
     * Each implementation of EncryptionMaterialsProvider can choose its own
     * strategy for loading encryption material.  For example, an
     * implementation might load encryption material from an existing key
     * management system, or load new encryption material when keys are
     * rotated.
     *
     * @return EncryptionMaterials which the caller can use to encrypt or
     * decrypt data.
    */
    @Override
    public EncryptionMaterials getEncryptionMaterials() {
        String kid = this.getKeyByName(this.keyName);
        return this.materialsCache.get(kid);
    }

    @Override
    public void refresh() {

    }
}
