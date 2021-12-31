package com.suvaditya.secureDataTransmission;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
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
        System.out.println("In generateNewSecretKey");
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256, SecureRandom.getInstanceStrong());
            SecretKey key = keyGenerator.generateKey();
            this.secretKey = key;
        }
        catch (NoSuchAlgorithmException e) {
            System.err.println("Algorithm could not be found or used.");
            e.printStackTrace();
        }
        catch (Exception e) {
            System.err.println("Internal error while creating new keys for AES");
            e.printStackTrace();
        }
    }

    private void generateIV() {
        System.out.println("In generateIV");
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        this.iv = iv;
    }

    private int[] byte2String(byte[] arr) {
        int[] res = new int[16];
        for(int i = 0; i<16; i++) {
            System.out.println(arr[i]);
            res[i] = (int) i;
            System.out.println(res[i]);
        }
        return res;
    }

    private byte[] String2byte(int[] arr) {
        byte[] res = new byte[16];
        for(int i = 0; i<16; i++) {
            System.out.println(arr[i]);
            res[i] = (byte) arr[i];
            System.out.println(res[i]);
        }
        return res;
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
        System.out.println("In encryptDataAES");
        final int TAG_LENGTH_BIT = 128;
        final String algorithm = "AES/GCM/NoPadding";
        String encryptedData = null;

        Map<String, String> results = new HashMap<String, String>();
        results.put("AESKey", null);
        results.put("DataB64", null);

        try {
            generateNewSecretKey();
            generateIV();
            String encryptedAesKey = null;

            RsaHelpers rsahelper = new RsaHelpers(databaseName, tableName);
            encryptedAesKey = rsahelper.encryptRawDataWithRsa(Hex.encodeHexString(this.secretKey.getEncoded()), uid); // encoding aes key in hex
            String str = Base64.getEncoder().encodeToString(this.iv);
            System.out.println("IV AS NORMAL STRING = " + str);
            byte[] newArr = Base64.getDecoder().decode(str);
            for(int i = 0; i<16; i++) {
                System.out.println(this.iv[i]);
                System.out.println(newArr[i]); 
            }
            encryptedAesKey = str + encryptedAesKey;
            // encryptedAesKey = this.iv.toString() + encryptedAesKey;
            // byte[] newEncryptedAesKeyWithIVPrepended = this.iv  tempEncryptedAesKey;
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, this.secretKey, new GCMParameterSpec(TAG_LENGTH_BIT, this.iv));
            byte[] dataBytes = data.getBytes();
            byte[] encryptedBytes = cipher.doFinal(dataBytes);

            Base64helpers helper = new Base64helpers();
            encryptedData = helper.encodeBytes(encryptedBytes);
            encryptedAesKey = Base64.getEncoder().encodeToString(encryptedAesKey.getBytes());

            results.put("AESKey", encryptedAesKey);
            results.put("DataB64", encryptedData);

            return results;
        }
        catch (NoSuchAlgorithmException e) {
            System.err.println("Algorithm could not be found or used.");
            e.printStackTrace();
        }
        catch (Exception e) {
            if (e.getMessage() == "KeysNotSet") {
                System.err.println("Keys are not set, leading to error in decryption. ");
            }
            System.err.println("Internal error while creating new keys for RSA");
            e.printStackTrace();
        }
        return results;
    }

    public String decryptData(Map<String, String> dataMap, String uid) {
        System.out.println("In decryptDataAES");
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

            // Base64helpers helper = new Base64helpers();
            // byte[] encryptedAesKeyBytesWithIvPrepended = helper.decodeString(encryptedAesKey).getBytes();
            byte[] aeskeyinbytes = Base64.getDecoder().decode(encryptedAesKey);
            String str = new String(aeskeyinbytes, StandardCharsets.UTF_8);
            String base64encodedIV = str.substring(0, 24);
            byte[] iv = Base64.getDecoder().decode(base64encodedIV);
            this.iv = iv;

            
            // byte[] encryptedAesKeyBytesWithIvPrepended = encryptedAesKey.getBytes();
            // this.iv = Arrays.copyOfRange(encryptedAesKeyBytesWithIvPrepended, 0, 15);
            
            String b64encodedAESkey = str.substring(24);
            String b64decryptedRSAencryptedAESkey = new String(Base64.getDecoder().decode(b64encodedAESkey), StandardCharsets.UTF_8);

            RsaHelpers rsahelper = new RsaHelpers(databaseName, tableName);
            decryptedAesKey = rsahelper.decryptRawDataWithRsa(b64decryptedRSAencryptedAESkey, uid);

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
            System.err.println("Algorithm could not be found or used.");
            e.printStackTrace();
        }
        catch (Exception e) {
            if (e.getMessage() == "KeysNotSet") {
                System.err.println("Keys are not set, leading to error in decryption. ");
            }
            System.err.println("Internal error while creating new keys for RSA");
            e.printStackTrace();
        }

        return decryptedData;
    }

}
