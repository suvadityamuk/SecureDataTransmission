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
        // final String uid = "ABCD1234UID";
        // final String data = "{data: hello}";

        final String uid = "test_uid";
        final String data = "test_data";

        // trying to emulate a simple json string since that is what will normally be done
        Map<String, String> result = helper.encryptData(data, uid);
        System.out.println("Main Result.get AESKEY = " + result.get("AESKey"));
        System.out.println("Main Result.get B64 = " + result.get("DataB64"));

        System.out.println("\n\n\n\n\n\n\n\n\n\n");

        System.out.println(helper.decryptData(result, uid));
    }
}
