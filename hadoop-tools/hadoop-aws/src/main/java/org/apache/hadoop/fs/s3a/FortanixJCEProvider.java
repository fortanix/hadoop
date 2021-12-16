package org.apache.hadoop.fs.s3a;

import com.fortanix.sdkms.jce.provider.SdkmsJCE;
import com.fortanix.sdkms.jce.provider.service.SdkmsKeyService;
import com.fortanix.sdkms.jce.provider.SdkmsSecretKey;

import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.model.EncryptionMaterials;
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider;
import com.amazonaws.services.s3.model.AmazonS3Exception;

import com.google.common.base.Preconditions;
import com.google.common.base.Strings;

import org.apache.hadoop.conf.Configurable;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.BasicConfigurator;


import java.io.Serializable;
import java.io.IOException;
import java.io.FileInputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Paths;
import java.nio.file.InvalidPathException;
import java.lang.NullPointerException;

import java.security.*;
import java.security.Provider;
import java.security.ProviderException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.SecretKey;

import java.util.ArrayList;
import java.util.TreeMap;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class FortanixJCEProvider implements EncryptionMaterialsProvider, Configurable {

    static final Logger LOGGER = Logger.getLogger(FortanixJCEProvider.class.getName());

    private final String ENDPOINT_DEFAULT = "https://sdkms.fortanix.com";
    private final String FXAPIKEY_DEFAULT = "OWFhM2QxYzYtM2NiYS00NDRiLWIwNWEtM2I5YmU1ZjEyZGNjOlNRUFJvU2pnNkxDQmtPanJMbnMtclE=";
    private final String ENDPOINT_CONF = "fs.s3a.cse.fortanixEndpoint";
    private final String APIKEY_CONF = "fs.s3a.cse.fortanixApiKey";

    private final String AES = "RSA";
    private final String RSA = "RSA";
    private final String KEY_TYPE_DEFAULT= RSA;

    private final String CSE_KEY_NAME_CONF = "fs.s3a.cse.encryption.keyname"; // hadoop conf reference to DSM key
    private final String CSE_MATERIAL_DESC = "jce_fortanix_key"; // S3 object metadata key reference

    private static SdkmsJCE providerJCE;

    private Configuration conf;
    private EncryptionMaterials materials;
    private String descValue;

    //public FortanixEncryptionMaterialsProvider(FortanixEncryptionMaterials materials) {
    //super(materials);

    public FortanixJCEProvider() {
        BasicConfigurator.configure();
        LOGGER.debug("Constructihg.. " + FortanixJCEProvider.class.getName());
        init(RSA);
    }

    public FortanixJCEProvider(String keyType) {
        BasicConfigurator.configure();
        LOGGER.debug("Constructihg.. " + FortanixJCEProvider.class.getName());
        init(keyType);
    }

    public FortanixJCEProvider(String keychainFilePath, String storePwd) {
        BasicConfigurator.configure();
        LOGGER.debug("Constructihg.. " + FortanixJCEProvider.class.getName());
        init(keychainFilePath, storePwd, RSA);
    }

    public FortanixJCEProvider(String keychainFilePath, String storePwd, String keyType) {
        BasicConfigurator.configure();
        LOGGER.debug("Constructihg.. " + FortanixJCEProvider.class.getName());
        init(keychainFilePath, storePwd, keyType);
    }

    public Provider getProviderInstance() {
        return this.providerJCE.getInstance(); //needed for .withCryptoProvider, but NOT USED.
    }

    // TBD JWT Auth
    private void initFortanix() {

        String strEndpoint = new String(ENDPOINT_DEFAULT);
        String strApiKey = new String("");
        LOGGER.debug("init Client..");

        if (conf != null && !Strings.isNullOrEmpty(conf.get(ENDPOINT_CONF))) {
            strEndpoint = conf.get(ENDPOINT_CONF);
        }
        if (conf != null && !Strings.isNullOrEmpty(conf.get(APIKEY_CONF))) {
            strApiKey = conf.get(APIKEY_CONF);
        } else {
            strApiKey = FXAPIKEY_DEFAULT;
        }
        LOGGER.debug("Trying to login with: " + strEndpoint);
        try {
            providerJCE = SdkmsJCE.initialize(strEndpoint, strApiKey); // explicit
            //providerJCE = new SdkmsJCE(); // defaults login to ENV vars

            if (Security.getProvider(providerJCE.getName()) == null) {

                boolean helloDebug = true;
                if (helloDebug == false)
                    Security.addProvider(providerJCE);
                else
                    Security.insertProviderAt(providerJCE, 5);
            }
            LOGGER.debug("Successful login");
        } catch (Exception e) {
            LOGGER.error("failure in logging in : " + e);
            throw new ProviderException(e.getMessage());
        }
    }

    private void init(String keyType) {
        // skip a Key Store
        try {
            initFortanix();

            if (conf != null) { 
                descValue = this.conf.get(CSE_KEY_NAME_CONF);
            } else {
                descValue = "s3_cse_key_"+keyType;
            }

            Preconditions.checkArgument(!Strings.isNullOrEmpty(descValue),
                    String.format("%s cannot be empty", CSE_KEY_NAME_CONF));

            if (keyType.equals(RSA)) {
                PrivateKey privateKey = null;
                PublicKey publicKey = null;

                LOGGER.debug("Getting RSA keys from DSM through JCE SdkmsKeyService");
                Key rsaPrivateKey = SdkmsKeyService.getKeyFromKeyObject(SdkmsKeyService.getSecurityObjectByName(descValue), false); // directly get RSA Private Key
                Key rsaPublicKey2 = SdkmsKeyService.getKeyFromKeyObject(SdkmsKeyService.toKeyObject(rsaPrivateKey), true);

                Key rsaPublicKey = SdkmsKeyService.getKeyFromKeyObject(SdkmsKeyService.getSecurityObjectByName(descValue), true);

                privateKey = (PrivateKey)rsaPrivateKey;
                publicKey = (PublicKey)rsaPublicKey;

                this.materials = new EncryptionMaterials(new KeyPair(publicKey, privateKey));

            } else { // AES
                LOGGER.debug("Getting AES key from DSM through JCE SdkmsKeyService");
                SecretKey aesSecretKey = (SecretKey)SdkmsKeyService.getKeyFromKeyObject(SdkmsKeyService.getSecurityObjectByName(descValue), false); // directly get AES Secret Key
                this.materials = new EncryptionMaterials(aesSecretKey);
            }
            this.materials.addDescription(CSE_MATERIAL_DESC, descValue);

        } catch (ProviderException | InvalidKeyException | NullPointerException e) {
            throw new RuntimeException(e);
        }
    }

    private void init(String keychainFilePath, String storePwd, String keyType) {
        // use a Key Store
        try {
            initFortanix();
            if (conf != null) { 
                descValue = this.conf.get(CSE_KEY_NAME_CONF);
            } else {
                // KeyStore alias (actual key in DSM has an extra suffix)
                if (keyType.equals(RSA))
                    descValue = "s3_cse_rsa_jce";
                else
                    descValue = "s3_cse_aes_jce";
            }

            Preconditions.checkArgument(!Strings.isNullOrEmpty(descValue),
                    String.format("%s cannot be empty", CSE_KEY_NAME_CONF));

            LOGGER.debug("Reading key store: " + keychainFilePath);
            // either SDKMS or sdkms-local as provider 
            // sdkms-local has the advantage of simple metadata available locally
            // both store types always refer to material inside DSM
            KeyStore keyStore = KeyStore.getInstance("SDKMS-local", providerJCE);
            try (FileInputStream fis = new FileInputStream(keychainFilePath)) {
                keyStore.load(fis, storePwd.toCharArray());
            } catch(IOException e) {
                LOGGER.error("failure in loading keystore : " + e);
                throw new IOException(e.getMessage());
            }

            if (keyType.equals(RSA)) {
                PrivateKey privateKey = null;
                PublicKey publicKey = null;

                LOGGER.debug("Getting RSA keys from DSM through JCE SdkmsKeyService");
                // defaults to RSA, unless constructor got AES? or use a setting specifying RSA or AES or different classes
                Key rsaPrivateKey = keyStore.getKey(descValue, storePwd.toCharArray());
                //publicKey = keyStore.getCertificate(descValue).getPublicKey(); // returns a Sun.RSA key rather than a RSAPublicKeyImp object from SdkmsJCE
                Key rsaPublicKey = SdkmsKeyService.getKeyFromKeyObject(SdkmsKeyService.toKeyObject(rsaPrivateKey), true);

                privateKey = (PrivateKey)rsaPrivateKey;
                publicKey = (PublicKey)rsaPublicKey;

                this.materials = new EncryptionMaterials(new KeyPair(publicKey, privateKey));

            } else {
                LOGGER.debug("Getting AES key from DSM through JCE SdkmsKeyService");
                Key aesKey = keyStore.getKey(descValue, storePwd.toCharArray());
                
                LOGGER.debug("Getting AES key from DSM through JCE SdkmsKeyService");
                SecretKey aesSecretKey = (SecretKey)SdkmsKeyService.getKeyFromKeyObject(SdkmsKeyService.toKeyObject(aesKey), false);
                this.materials = new EncryptionMaterials(aesSecretKey);
            }
            this.materials.addDescription(CSE_MATERIAL_DESC, descValue);

        } catch (ProviderException | IOException | NoSuchAlgorithmException | KeyStoreException | InvalidKeyException | CertificateException | UnrecoverableKeyException | NullPointerException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
        public EncryptionMaterials getEncryptionMaterials(Map<String, String> materialsDescription) {
            if (materialsDescription == null
                    || materialsDescription.get(CSE_MATERIAL_DESC) == null
                    || descValue.equals(materialsDescription.get(CSE_MATERIAL_DESC))) {
                return this.materials;
            } else {
                throw new RuntimeException(
                        String.format("RSA key pair (%s: %s) doesn't match with the materials description", CSE_MATERIAL_DESC, descValue));
            }
        }

    @Override
        public EncryptionMaterials getEncryptionMaterials() {
            if (this.materials != null) {
                return this.materials;
            } else {
                throw new RuntimeException("RSA key pair is not initialized.");
            }
        }

    @Override
        public void refresh() {

        }

    @Override
        public Configuration getConf() {
            return this.conf;
        }

    @Override
        public void setConf(Configuration conf) {
            this.conf = conf;
        }

}
