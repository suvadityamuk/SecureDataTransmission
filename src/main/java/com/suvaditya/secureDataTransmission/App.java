package com.suvaditya.secureDataTransmission;
import java.util.*;

// import java.util.Scanner;

/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args )
    {
        AesHelpers helper = new AesHelpers();
        final String uid = "ABCD1234UID";
        final String data = "{data: hello}";
        // trying to emulate a simple json string since that is what will normally be done
        Map<String, String> result = helper.encryptData(data, uid);
        System.out.println("Main Result.get AESKEY = " + result.get("AESKey"));
        System.out.println("Main Result.get B64 = " + result.get("DataB64"));

        System.out.println("\n\n\n\n\n\n\n\n\n\n");

        System.out.println(helper.decryptData(result, uid));

        // DatabaseHelpers helper = new DatabaseHelpers();
        // // helper.createNewDatabase("test1");
        // String dbName = "test1";
        // String tableName = "bruh1";
        // helper.createTable(dbName, tableName);
        // String uid = "ABCD1234EFGH5678";
        // String publickey = "123ABC456DEF";
        // String privatekey = "XYZ123ABC456";
        // helper.insertKeysToDatabase(dbName, tableName, uid, publickey, privatekey);
        // Map<String, String> readKeys = helper.readKeysFromDatabase(dbName, tableName, uid);
        // System.out.println(readKeys.get("PrivateKey"));
        // // CHECK CASE IN ALL USE OF HASHMAPS KEY AND VALUE
        // System.out.println(readKeys.get("PublicKey"));
        // String newPublicKey = "01234ABCDEF56";
        // helper.updateKeysInDatabase(dbName, tableName, uid, newPublicKey, privatekey);
        // Map<String, String> readKeys2 = helper.readKeysFromDatabase(dbName, tableName, uid);
        // System.out.println(readKeys2.get("PrivateKey"));
        // // CHECK CASE IN ALL USE OF HASHMAPS KEY AND VALUE
        // System.out.println(readKeys2.get("PublicKey"));
        // helper.deleteKeysFromDatabase(dbName, tableName, uid);
        // Map<String, String> readKeys3 = helper.readKeysFromDatabase(dbName, tableName, uid);
        // System.out.println(readKeys3.get("PrivateKey"));
        // // CHECK CASE IN ALL USE OF HASHMAPS KEY AND VALUE
        // System.out.println(readKeys3.get("PublicKey"));



        // System.out.println( "Hello World!" );
        // Base64helpers base64helpers = new Base64helpers();
        // System.out.println("Hi! Enter text to encode.");
        // Scanner sc = new Scanner(System.in);
        // String inp = sc.nextLine();
        // String result = "Bruh, did not work.";
        // try {
        //     result = base64helpers.encode(inp);
        // }
        // catch (Exception e) {
        //     e.printStackTrace();
        // }
        // System.out.println(result);
        // System.out.println("Decoded text");
        // String res2 = base64helpers.decode(result);
        // System.out.println(res2);
        // sc.close();
    }
}
