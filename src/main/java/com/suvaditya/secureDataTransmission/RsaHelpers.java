package com.suvaditya.secureDataTransmission;

import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

import javax.crypto.Cipher;

import java.io.*;

public class RsaHelpers {

    /**
     * Functions: 
     * generateNewKeys()
     * loadKeyPairFromDatabase(String databaseName, String tableName, String uid)
     * saveNewKeypairToDatabase(String databaseName, String tableName, String uid)
     * encryptRawDataWithRsa(String data, String uid)
     * decryptRawDataWithRsa(String data, String uid)
     * encryptFileWithRsa(String pathToFile, String uid, String fileExtension)
     * decryptFileWithRsa(String pathToFile, String uid, String fileExtension)
     */
    
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

    

    private void generateNewKeys() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            this.privateKey = pair.getPrivate();
            this.publicKey = pair.getPublic();
        }
        catch (NoSuchAlgorithmException e) {
            System.out.println("Algorithm could not be found or used.");
            e.printStackTrace();
        }
        catch (Exception e) {
            System.out.println("Internal error while creating new keys for RSA");
            e.printStackTrace();
        }
    }

    public boolean loadKeyPairFromDatabase(String databaseName, String tableName, String uid) {
        /*
        Check if db exists
        if yes, then query and load keypairs
        if no, then throw error
         */
        boolean result = false;
        try {
            String currentWorkingDir = FileSystems.getDefault().getPath("").toAbsolutePath().toString();
            System.out.println(currentWorkingDir);
            String filePath = String.format("jdbc:sqlite:%s", currentWorkingDir) + String.format("/%s", databaseName) + ".db";
            File file = new File(filePath);
            if (file.exists()) {
                Map<String, byte[]> keyPair = helper.readKeysFromDatabase(databaseName, tableName, uid);

                byte[] privateKeyBytes = keyPair.get("PrivateKey");
                byte[] publicKeyBytes = keyPair.get("PublicKey");

                KeyFactory keyFactory = KeyFactory.getInstance("RSA");

                EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
                EncodedKeySpec privateKeySpec = new X509EncodedKeySpec(privateKeyBytes);

                this.publicKey = keyFactory.generatePublic(publicKeySpec);
                this.privateKey = keyFactory.generatePrivate(privateKeySpec);
                result = true;
            }
        }
        catch (NoSuchAlgorithmException e) {
            System.out.println("Algorithm could not be found or used.");
            e.printStackTrace();
        }
        catch (Exception e) {
            System.out.println("Internal error while loading keys from RSA");
            e.printStackTrace();
        }
        return result;
    }

    private boolean saveNewKeypairToDatabase(String databaseName, String tableName, String uid) {
        boolean result = false;
        if (this.privateKey == null || this.publicKey == null) {
            generateNewKeys();
        }
        this.helper.insertKeysToDatabase(databaseName, tableName, uid, this.publicKey, this.privateKey);
        if (this.privateKey != null && this.publicKey != null) {
            result = true;
        }
        return result;
    }

    public String encryptRawDataWithRsa(String data, String uid) {
        /*
        Check if instance has keys loaded. 
        if yes, use to encrypt
        if not, create new keys and save into database against uid and then encrypt

        enc: string message -> bytes -> cipher-bytes -> b64 string

        dec: b64 string -> cipher-bytes -> bytes -> string

         */
        String encryptedCipherText = null;
        try {

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

            Base64helpers b64helper = new Base64helpers();

            encryptedCipherText = b64helper.encodeBytes(encryptedDataBytes);
            return encryptedCipherText;
        }
        catch (NoSuchAlgorithmException e) {
            System.out.println("Algorithm could not be found or used.");
            e.printStackTrace();
        }
        catch (Exception e) {
            System.out.println("Internal error while creating new keys for RSA");
            e.printStackTrace();
        }
        return encryptedCipherText;
    }

    public String decryptRawDataWithRsa(String data, String uid) {
        String decryptedText = null;
        try {
            if (this.privateKey == null || this.publicKey == null) {
                loadKeyPairFromDatabase(this.databaseName, this.tableName, uid);
                if (this.privateKey == null || this.publicKey == null) {
                    throw new Exception("KeysNotSet");
                }
            }

            Cipher decryptor = Cipher.getInstance("RSA");

            Base64helpers b64helper = new Base64helpers();

            decryptor.init(Cipher.DECRYPT_MODE, this.privateKey);
            byte[] dataBytes = b64helper.decodeString(data).getBytes(StandardCharsets.UTF_8);
            byte[] decryptedDataBytes = decryptor.doFinal(dataBytes);

            decryptedText = new String(decryptedDataBytes, StandardCharsets.UTF_8);
            return decryptedText;
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
        return decryptedText;
    }
    
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
            System.out.println("Algorithm could not be found or used.");
            e.printStackTrace();
        }
        catch (FileNotFoundException e) {
            System.out.println("Requested could not be found or used. Path may be broken");
            e.printStackTrace();
        } 
        catch (IOException e) {
            System.out.println("I/O Error. File-handles may be facing a problem.");
            e.printStackTrace();
        }
        catch (Exception e) {
            if (e.getMessage() == "KeysNotSet") {
                System.out.println("Keys are not set, leading to error in decryption. ");
            }
            System.out.println("Internal error while creating new keys for RSA");
            e.printStackTrace();
        }
    }

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
            System.out.println("Algorithm could not be found or used.");
            e.printStackTrace();
        }
        catch (FileNotFoundException e) {
            System.out.println("Requested could not be found or used. Path may be broken");
            e.printStackTrace();
        } 
        catch (IOException e) {
            System.out.println("I/O Error. File-handles may be facing a problem.");
            e.printStackTrace();
        }
        catch (Exception e) {
            if (e.getMessage() == "KeysNotSet") {
                System.out.println("Keys are not set, leading to error in decryption. ");
            }
            System.out.println("Internal error while creating new keys for RSA");
            e.printStackTrace();
        }
    }
    
}
