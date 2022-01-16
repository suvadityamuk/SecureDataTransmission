package com.suvaditya.secureDataTransmission;

import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import javax.crypto.Cipher;
import org.apache.commons.codec.binary.Hex;
import java.io.*;

/**
 * public class RsaHelpers
 * @author Suvaditya Mukherjee <suvadityamuk@gmail.com>
 * @version 1.0.0
 * @param
 * <p>
 * <b>Dependencies</b>:
 *  {@code java.security.spec.*, java.nio.charset.StandardCharsets, java.nio.file.*, java.util.*, java.io.*, javax.crypto.Cipher, org.apache.commons.codec.binary.Hex} 
 * </p>
 * <p>
 * <b>Private Variables</b>:<br>
 *  1) java.security.PublicKey publicKey <br>
 *  2) java.security.PrivateKey privateKey <br>
 *  3) DatabaseHelpers helper <br>
 *  4) String databaseName <br>
 *  5) String tableName <br>
 * </p>
 * <p>
 * <b>Methods available</b>:<br>
 *  1) private generateNewKeys()<br>
 *  2) public loadKeyPairFromDatabase()<br>
 *  3) public saveNewKeypairToDatabase()<br>
 *  4) public encryptRawDataWithRsa()<br>
 *  5) public decryptRawDataWithRsa()<br>
 *  6) public encryptFileWithRsa()<br>
 *  7) public decryptFileWithRsa()<br>
 * </p>
 */

public class RsaHelpers {
    
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private DatabaseHelpers helper;
    private String databaseName;
    private String tableName;

    RsaHelpers() {
        privateKey = null;
        publicKey = null;
        databaseName = null;
        tableName = null;
        helper = new DatabaseHelpers();
    }

    RsaHelpers(PrivateKey privateKey, PublicKey publicKey, String databaseName, String tableName) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.databaseName = databaseName;
        this.tableName = tableName;
        this.helper = new DatabaseHelpers();
    }

    RsaHelpers(String databaseName, String tableName) {
        privateKey = null;
        publicKey = null;
        this.databaseName = databaseName;
        this.tableName = tableName;
        helper = new DatabaseHelpers();
    }

    /**
     * Returns a newly generated keypair for RSA-2048 encryption.
     * @param None
     * @return void  
     */
    private void generateNewKeys() {
        System.out.println("In generateNewKeys");
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            this.privateKey = pair.getPrivate();
            this.publicKey = pair.getPublic();
        }
        catch (NoSuchAlgorithmException e) {
            System.err.println("Algorithm could not be found or used.");
            e.printStackTrace();
        }
        catch (Exception e) {
            System.err.println("Internal error while creating new keys for RSA");
            e.printStackTrace();
        }
    }

    /**
     * Initialises instance PrivateKey and PublicKey variables by using the database and querying the presence of a keypair against supplied UID. If yes,
     * reads the keys, encodes and loads them as proper PublicKey and PrivateKey.
     * @param databaseName
     * @param tableName
     * @param uid
     * @return boolean
     */
    public boolean loadKeyPairFromDatabase(String databaseName, String tableName, String uid) {
        /*
        Check if db exists
        if yes, then query and load keypairs
        if no, then throw error
         */
        System.out.println("In loadKeyPairFromDatabase");
        boolean result = false;
        try {
            String currentWorkingDir = FileSystems.getDefault().getPath("").toAbsolutePath().toString();
            String filePath = currentWorkingDir + String.format("/%s", databaseName) + ".sqlite";
            File file = new File(filePath);
            if (!file.exists()) {
                helper.createNewDatabase(databaseName, tableName);
            }
            else if (file.exists()) {
                Map<String, byte[]> keyPair = helper.readKeysFromDatabase(databaseName, tableName, uid);

                byte[] privateKeyBytes = keyPair.get("PrivateKey");
                byte[] publicKeyBytes = keyPair.get("PublicKey");
                if (publicKeyBytes == null || privateKeyBytes == null) {
                    System.out.println("Private and public key bytes are null");
                } 

                KeyFactory keyFactory = KeyFactory.getInstance("RSA");

                EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);

                PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);

                this.publicKey = keyFactory.generatePublic(publicKeySpec);
                this.privateKey = keyFactory.generatePrivate(privateKeySpec);
                
                result = true;
            }
        }
        catch (NoSuchAlgorithmException e) {
            System.err.println("Algorithm could not be found or used.");
            e.printStackTrace();
        }
        catch (Exception e) {
            System.err.println("Internal error while loading keys from RSA");
            e.printStackTrace();
        }
        return result;
    }

    /**
     * Saves the instance PublicKey and PrivateKey into the database against the supplied UID.
     * @param databaseName
     * @param tableName
     * @param uid
     * @return boolean
     */
    private boolean saveNewKeypairToDatabase(String databaseName, String tableName, String uid) {
        System.out.println("In saveNewKeypairToDatabase");
        boolean result = false;
        if (this.privateKey == null || this.publicKey == null) {
            generateNewKeys();
        }
        if (this.privateKey != null && this.publicKey != null) {
            this.helper.insertKeysToDatabase(databaseName, tableName, uid, this.publicKey, this.privateKey);
        } 
        if (this.privateKey != null && this.publicKey != null) {
            result = true;
        }
        return result;
    }

    /**
     * Encrypt String data using RSA-2048 encryption. If instance has keys loaded, it is used to encrypt the data directly.
     * If not, keys are first generated, saved into the database against the UID and then encryption-process begins.
     * @param data
     * @param uid
     * @return String 
     */
    public String encryptRawDataWithRsa(String data, String uid) {
        /*
        Check if instance has keys loaded. 
        if yes, use to encrypt
        if not, create new keys and save into database against uid and then encrypt

        enc: string message -> bytes -> cipher-bytes -> b64 string

        dec: b64 string -> cipher-bytes -> bytes -> string

         */
        System.out.println("In encryptRawDataWithRsa");
        String encryptedCipherText = null;
        try {
            // If loading keys for first time
            if (this.privateKey == null || this.privateKey == null) {
                loadKeyPairFromDatabase(this.databaseName, this.tableName, uid);
                if (this.privateKey == null || this.publicKey == null) {
                    generateNewKeys();
                    saveNewKeypairToDatabase(databaseName, tableName, uid);
                    System.out.println("No keys found against this UID. New ones generated and saved into database.");
                }
            }
            
            Cipher encryptor = Cipher.getInstance("RSA");
            encryptor.init(Cipher.ENCRYPT_MODE, this.publicKey);
            byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
            byte[] encryptedDataBytes = encryptor.doFinal(dataBytes);

            encryptedCipherText = new String(encryptedDataBytes, StandardCharsets.UTF_8);
            encryptedCipherText = Hex.encodeHexString(encryptedDataBytes);
            return encryptedCipherText;
        }
        catch (NoSuchAlgorithmException e) {
            System.err.println("Algorithm could not be found or used.");
            e.printStackTrace();
        }
        catch (Exception e) {
            System.err.println("Internal error while creating new keys for RSA");
            e.printStackTrace();
        }
        return encryptedCipherText;
    }

    /**
     * Decrypt ciphertext generated from RSA-2048 encryption with valid keys. Checks if instance has keys present, otherwise loads them from 
     * database against UID and continues decryption process.
     * @param data
     * @param uid
     * @return String
     */
    public String decryptRawDataWithRsa(String data, String uid) {
        System.out.println("In decryptRawDataWithRsa");
        String decryptedText = null;
        try {
            if (this.privateKey == null || this.publicKey == null) {
                loadKeyPairFromDatabase(this.databaseName, this.tableName, uid);
                if (this.privateKey == null || this.publicKey == null) {
                    throw new RuntimeException("KeysNotSet");
                }
            }

            Cipher decryptor = Cipher.getInstance("RSA/ECB/PKCS1Padding");

            decryptor.init(Cipher.DECRYPT_MODE, this.privateKey);
            byte[] dataBytes = Hex.decodeHex(data);
            dataBytes = decryptor.doFinal(dataBytes);
            decryptedText = new String(dataBytes, StandardCharsets.UTF_8);
            return decryptedText;
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
        return decryptedText;
    }
    
    /**
     * WORK IN PROGRESS, DO NOT USE
     */
    public void encryptFileWithRsa(String pathToFile, String uid, String fileExtension) {
        if (fileExtension.charAt(0) != '.') {
            System.out.println("File Extension incorrect. Please check it carefully.");
            return;
        }
        try {
            File fileToEncrypt = new File(pathToFile);
            FileInputStream fileInputStream = new FileInputStream(fileToEncrypt);
            byte[] buffer = new byte[1024];
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

            while(true) {
                int read_len = fileInputStream.read(buffer, 0, buffer.length);
                if (read_len <= 0) {
                    break;
                }
                byteArrayOutputStream.write(buffer, 0, read_len);
            }

            fileInputStream.close();

            byte[] fileToEncryptBytes = byteArrayOutputStream.toByteArray();
            byteArrayOutputStream.close();


            Cipher encryptor = Cipher.getInstance("RSA");
            encryptor.init(Cipher.ENCRYPT_MODE, this.publicKey);
            byte[] encryptedBytes = encryptor.doFinal(fileToEncryptBytes);

            String currentWorkingDir = FileSystems.getDefault().getPath("").toAbsolutePath().toString();
            String newEncryptedFilePath = currentWorkingDir + "encrypted_" + uid + fileExtension;
            File newEncryptedFile = new File(newEncryptedFilePath);


            if (newEncryptedFile.createNewFile()) {
                System.out.println("New File created : " + newEncryptedFilePath);
            }
            else {
                System.out.println("File already exists : " + newEncryptedFilePath + "\nOverwriting...");
            }

            FileOutputStream fileOutputStream = new FileOutputStream(newEncryptedFile);
            fileOutputStream.write(encryptedBytes);
            fileOutputStream.flush();
            fileOutputStream.close();
            System.out.println("New encrypted file stored at : " + newEncryptedFilePath);

        }
        catch (NoSuchAlgorithmException e) {
            System.err.println("Algorithm could not be found or used.");
            e.printStackTrace();
        }
        catch (FileNotFoundException e) {
            System.err.println("Requested could not be found or used. Path may be broken");
            e.printStackTrace();
        } 
        catch (IOException e) {
            System.err.println("I/O Error. File-handles may be facing a problem.");
            e.printStackTrace();
        }
        catch (Exception e) {
            if (e.getMessage() == "KeysNotSet") {
                System.err.println("Keys are not set, leading to error in decryption. ");
            }
            System.err.println("Internal error while creating new keys for RSA");
            e.printStackTrace();
        }
    }

    /**
     * WORK IN PROGRESS, DO NOT USE
     * @param pathToFile
     * @param uid
     * @param fileExtension
     */
    public void decryptFileWithRsa(String pathToFile, String uid, String fileExtension) {
        if (fileExtension.charAt(0) != '.') {
            System.out.println("File Extension incorrect. Please check it carefully.");
            return;
        }
        try {
            File fileToDecrypt = new File(pathToFile);
            FileInputStream fileInputStream = new FileInputStream(fileToDecrypt);
            byte[] buffer = new byte[1024];
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

            while(true) {
                int read_len = fileInputStream.read(buffer, 0, buffer.length);
                if (read_len <= 0) {
                    break;
                }
                byteArrayOutputStream.write(buffer, 0, read_len);
            }

            fileInputStream.close();

            byte[] fileToDecryptBytes = byteArrayOutputStream.toByteArray();
            byteArrayOutputStream.close();


            Cipher decryptor = Cipher.getInstance("RSA");
            decryptor.init(Cipher.DECRYPT_MODE, this.privateKey);
            byte[] encryptedBytes = decryptor.doFinal(fileToDecryptBytes);

            String currentWorkingDir = FileSystems.getDefault().getPath("").toAbsolutePath().toString();
            String newDecryptedFilePath = currentWorkingDir + "decrypted_" + uid + fileExtension;
            File newDecryptedFile = new File(newDecryptedFilePath);


            if (newDecryptedFile.createNewFile()) {
                System.out.println("New File created : " + newDecryptedFilePath);
            }
            else {
                System.out.println("File already exists : " + newDecryptedFilePath + "\nOverwriting...");
            }

            FileOutputStream fileOutputStream = new FileOutputStream(newDecryptedFile);
            fileOutputStream.write(encryptedBytes);
            fileOutputStream.flush();
            fileOutputStream.close();
            System.out.println("New decrypted file stored at : " + newDecryptedFilePath);

        }
        catch (NoSuchAlgorithmException e) {
            System.err.println("Algorithm could not be found or used.");
            e.printStackTrace();
        }
        catch (FileNotFoundException e) {
            System.err.println("Requested could not be found or used. Path may be broken");
            e.printStackTrace();
        } 
        catch (IOException e) {
            System.err.println("I/O Error. File-handles may be facing a problem.");
            e.printStackTrace();
        }
        catch (Exception e) {
            if (e.getMessage() == "KeysNotSet") {
                System.err.println("Keys are not set, leading to error in decryption. ");
            }
            System.err.println("Internal error while creating new keys for RSA");
            e.printStackTrace();
        }
    }
    
}
