package com.suvaditya.secureDataTransmission;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import java.util.Map;
import org.junit.Test;

/**
 * Unit test for simple App.
 */
public class AppTest 
{
    /**
     * Rigorous Test :-)
     */
    @Test
    public void shouldAnswerWithTrue()
    {
        assertTrue( true );
    }

    @Test
    public void encryption() 
    {
        AesHelpers helper = new AesHelpers();
        final String uid = "test_uid";
        final String data = "test_data";

        Map<String, String> result = helper.encryptData(data, uid);

        boolean res1 = false;
        boolean res2 = false;
        if (result.get("AESKey").length() == 716) {
            res1 = true;
        }
        if (result.get("DataB64").length() == 36) {
            res2 = true;
        }
        assertTrue("Encryption test Passed", res1 == true && res2 == true);
        
    }

    @Test
    public void decryptionAfterEncryption() 
    {
        AesHelpers helper = new AesHelpers();
        final String uid = "test_uid";
        final String data = "test_data";

        Map<String, String> result = helper.encryptData(data, uid);

        String res = helper.decryptData(result, uid);
        assertEquals(data, res);
    }

    @Test
    public void checkDatabaseForKeysDirectly() 
    {
        DatabaseHelpers helper = new DatabaseHelpers();
        final String databaseName = "main_database";
        final String tableName = "key_data";
        final String uid = "test_uid";
        Map<String, byte[]> res = helper.readKeysFromDatabase(databaseName, tableName, uid);
        assertTrue("Keys exist in database", ((res.get("PrivateKey") != null) && (res.get("PublicKey") != null)));
    }
}
