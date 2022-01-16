package com.suvaditya.secureDataTransmission;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * public class AesHelpers()
 * 
 * @author  Suvaditya Mukherjee <suvadityamuk@gmail.com>
 * @version 1.0.0
 * @param
 * <p>
 * <b>Dependencies</b>:
 *  {@code org.apache.commons.codec.binary.Hex, java.nio.charset.StandardCharsets, java.security, java.util} 
 * </p>
 * <p>
 * <b>Private Variables</b>:<br>
 *  1) javax.crypto.SecretKey secretkey <br>
 *  2) byte[] iv <br>
 *  3) String databaseName <br>
 *  4) String tableName <br>
 * </p>
 * <p>
 * <b>Methods available</b>:<br>
 *  1) private generateNewSecretKey<br>
 *  2) private generateIV<br>
 *  3) public encryptData<br>
 *  4) public decryptData<br>
 * </p>
 */
public class AesHelpers {
    private SecretKey secretKey;
    private byte[] iv;

    private static final String databaseName = "main_database";
    private static final String tableName = "key_data";

    AesHelpers() {
        secretKey = null;
        iv = null;
    }
    /**
     * Returns a newly generated key for AES-256 encryption.
     * @param None
     * @return void  
     */
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

    /**
     * Returns a randomly-generated 16-byte array used as Initialisation Vector
     * @param None
     * @return void 
     */
    private void generateIV() {
        System.out.println("In generateIV");
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        this.iv = iv;
    }

    /**
     * <p>
     * Encrypt String-based data. Requires user UID to validate and perform other internal functions.<br><br>
     * 
     * It will first generate a new AES Key and a corresponding IV. Using UID, it will check if a RSA-2048 key 
     * exists against that UID. <br><br>If yes, it will query, load and encrypt the AES Key with RSA-2048 encryption.
     * <br><br>If not found, new RSA-2048 keys will be generated and loaded into the database against the UID provided. <br><br>
     * 
     * It will then initialise a Cipher and encrypt the original String data using the AES key previously generated. 
     * </p>
     * @param data
     * @param uid
     * @return <b>Map &lt String, String &gt</b><br><br>
     * <b>AESKey</b>: AES-Key in Base64 format with IV prepended <br><br>
     * <b>DataB64</b>: Ciphertext in Base64 format
     */
    public Map<String, String> encryptData(String data, String uid) {

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

            encryptedAesKey = str + encryptedAesKey;
            
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, this.secretKey, new GCMParameterSpec(TAG_LENGTH_BIT, this.iv));
            byte[] dataBytes = data.getBytes();
            byte[] encryptedBytes = cipher.doFinal(dataBytes);

            encryptedData = Base64.getEncoder().encodeToString(encryptedBytes);
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

    /**
     * <p>
     * Decrypt ciphertext. Requires user UID to validate and perform other internal functions.<br><br>
     * 
     * The UID will be used to query the internal database to find if a RSA-2048 key exists. <br><br>If it does, only then will
     * it go ahead and decrypt the AES key using that RSA-2048 key. <br><br>If no key exists, a RuntimeError is thrown.
     * The AES-IV is also taken out and reproduced for use.
     * Once the AES key is decrypted, it is used to decrypt the actual data present.
     * </p>
     * @param dataMap <br><br>
     * <b>AESKey</b>: AES-Key in Base64 format with IV prepended <br><br>
     * <b>DataB64</b>: Ciphertext in Base64 format
     * @param uid
     * @return String
     */
    public String decryptData(Map<String, String> dataMap, String uid) {

        final int TAG_LENGTH_BIT = 128;
        final String algorithm = "AES/GCM/NoPadding";
        String decryptedData = null;

        String data = dataMap.get("DataB64");
        String encryptedAesKey = dataMap.get("AESKey");

        try {
            String decryptedAesKey = null;

            byte[] aeskeyinbytes = Base64.getDecoder().decode(encryptedAesKey);
            String str = new String(aeskeyinbytes, StandardCharsets.UTF_8);
            String base64encodedIV = str.substring(0, 24);
            byte[] iv = Base64.getDecoder().decode(base64encodedIV);
            this.iv = iv;
            
            String b64encodedAESkey = str.substring(24, str.length());

            RsaHelpers rsahelper = new RsaHelpers(databaseName, tableName);
            decryptedAesKey = rsahelper.decryptRawDataWithRsa(b64encodedAESkey, uid);

            byte[] bytesKey = decryptedAesKey.getBytes();
            String newkey = new String(bytesKey, StandardCharsets.UTF_8);
            this.secretKey = new SecretKeySpec(Hex.decodeHex(newkey), 0, Hex.decodeHex(newkey).length, "AES");

            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, this.secretKey, new GCMParameterSpec(TAG_LENGTH_BIT, this.iv));
            byte[] dataBytes = Base64.getDecoder().decode(data);
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
