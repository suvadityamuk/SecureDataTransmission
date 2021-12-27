package com.suvaditya.secureDataTransmission;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class AesHelpers {
    private SecretKey secretKey;
    private byte[] iv;

    private static final String databaseName = "main_database";
    private static final String tableName = "key_data";

    AesHelpers() {
        secretKey = null;
        iv = null;
    }
    
    private void generateNewSecretKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(512, SecureRandom.getInstanceStrong());
            SecretKey key = keyGenerator.generateKey();
            this.secretKey = key;
        }
        catch (NoSuchAlgorithmException e) {
            System.out.println("Algorithm could not be found or used.");
            e.printStackTrace();
        }
        catch (Exception e) {
            System.out.println("Internal error while creating new keys for AES");
            e.printStackTrace();
        }
    }

    private void generateIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        this.iv = iv;
    }

    public Map<String, String> encryptData(String data, String uid) {


        /*
        generate new aes key and iv
        check if uid has rsa key from db. 
        if yes -> use that to encrypt aes key
        if no -> (create new rsa keys and store in db)  - handled in rsa side and encrypt aes
        encrypt data in utf8 string type with og aes key as bytes and store as b64 string
        return data and aes key as strings
         */

        final int TAG_LENGTH_BIT = 128;
        final String algorithm = "AES/GCM/NoPadding";
        String encryptedData = null;
        final String databaseName = "main_database";
        final String tableName = "key_data";

        Map<String, String> results = new HashMap<String, String>();
        results.put("AESKey", null);
        results.put("DataB64", null);

        try {
            generateNewSecretKey();
            generateIV();
            String encryptedAesKey = null;

            RsaHelpers rsahelper = new RsaHelpers(databaseName, tableName);
            encryptedAesKey = rsahelper.encryptRawDataWithRsa(this.secretKey.toString(), uid);

            // encryptedAesKey = this.iv + encryptedAesKey;
            byte[] tempEncryptedAesKey = encryptedAesKey.getBytes();
            // byte[] newEncryptedAesKeyWithIVPrepended = this.iv  tempEncryptedAesKey;
            byte[] newEncryptedAesKeyWithIVPrependedAsBytes = new byte[tempEncryptedAesKey.length + 16];
            for(int i = 0; i<16; i++) {
                newEncryptedAesKeyWithIVPrependedAsBytes[i] = this.iv[i];
            }
            System.arraycopy(tempEncryptedAesKey, 0, newEncryptedAesKeyWithIVPrependedAsBytes, 16, 16);
            encryptedAesKey = new String(newEncryptedAesKeyWithIVPrependedAsBytes, StandardCharsets.UTF_8);

            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, this.secretKey, new GCMParameterSpec(TAG_LENGTH_BIT, this.iv));
            byte[] dataBytes = data.getBytes();
            byte[] encryptedBytes = cipher.doFinal(dataBytes);

            Base64helpers helper = new Base64helpers();
            encryptedData = helper.encodeBytes(encryptedBytes);

            results.put("AESKey", encryptedAesKey);
            results.put("DataB64", encryptedData);

            return results;
        }
        catch (NoSuchAlgorithmException e) {
            System.out.println("Algorithm could not be found or used.");
            e.printStackTrace();
        }
        catch (Exception e) {
            if (e.getMessage() == "KeysNotSet") {
                System.out.println("Keys are not set, leading to error in decryption. ");
            }
            System.out.println("Internal error while creating new keys for RSA");
            e.printStackTrace();
        }
        return results;
    }

    public String decryptData(Map<String, String> dataMap, String uid) {

        /*
        Check uid for rsa keys
        if found -> use that to decrypt aes key
        if not found -> throw error
        take data and convert from b64 to byte[]
        decrypt data bytes
        make into utf8 string
        return string
         */

        final int TAG_LENGTH_BIT = 128;
        final String algorithm = "AES/GCM/NoPadding";
        String decryptedData = null;

        String data = dataMap.get("DataB64");
        String encryptedAesKey = dataMap.get("AESKey");

        try {
            String decryptedAesKey = null;
            
            byte[] encryptedAesKeyBytesWithIvPrepended = encryptedAesKey.getBytes();
            this.iv = Arrays.copyOfRange(encryptedAesKeyBytesWithIvPrepended, 0, 15);
            
            byte[] onlyAesKeyBytes = new byte[encryptedAesKeyBytesWithIvPrepended.length - 16];
            for(int i = 16; i<encryptedAesKeyBytesWithIvPrepended.length; i++) {
                onlyAesKeyBytes[i-16] = encryptedAesKeyBytesWithIvPrepended[i];
            }
            encryptedAesKey = new String(onlyAesKeyBytes, StandardCharsets.UTF_8);
            
            RsaHelpers rsahelper = new RsaHelpers(databaseName, tableName);
            decryptedAesKey = rsahelper.decryptRawDataWithRsa(encryptedAesKey, uid);

            byte[] bytesKey = decryptedAesKey.getBytes();
            this.secretKey = new SecretKeySpec(bytesKey, 0, bytesKey.length, "AES");

            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, this.secretKey, new GCMParameterSpec(TAG_LENGTH_BIT, this.iv));
            byte[] dataBytes = data.getBytes();
            byte[] decryptedBytes = cipher.doFinal(dataBytes);

            decryptedData = new String(decryptedBytes, StandardCharsets.UTF_8);

            return decryptedData;

        }
        catch (NoSuchAlgorithmException e) {
            System.out.println("Algorithm could not be found or used.");
            e.printStackTrace();
        }
        catch (Exception e) {
            if (e.getMessage() == "KeysNotSet") {
                System.out.println("Keys are not set, leading to error in decryption. ");
            }
            System.out.println("Internal error while creating new keys for RSA");
            e.printStackTrace();
        }

        return decryptedData;
    }

}
