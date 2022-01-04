package com.suvaditya.secureDataTransmission;

import java.sql.*;
import java.nio.file.*;
import java.util.*;

import org.apache.commons.codec.binary.Hex;

import java.security.*;

/**
 * public class DatabaseHelpers()
 * @author Suvaditya Mukherjee <suvadityamuk@gmail.com>
 * @version 1.0.0
 * @param
 * <p>
 * <b>Dependencies</b>:
 *  {@code org.apache.commons.codec.binary.Hex, java.sql.*, java.security.*, java.util.*, java.nio.file.*} 
 * </p>
 * <p>
 * <b>Private Variables</b>:<br>
 *  1) java.sql.Connection conn <br>
 *  2) String dbPath <br>
 * </p>
 * <p>
 * <b>Methods available</b>:<br>
 *  1) private connectToDb()<br>
 *  2) private closeDbConnection()<br>
 *  3) public setDatabasePath()<br>
 *  4) public createNewDatabase()<br>
 *  5) public createTable()<br>
 *  6) public insertKeysToDatabase()<br>
 *  7) public readKeysFromDatabase()<br>
 *  8) public updateKeysInDatabase()<br>
 *  9) public deleteKeysFromDatabase()<br>
 * </p>
 */

public class DatabaseHelpers {
    
    Connection conn;
    String dbPath;
    
    DatabaseHelpers() {
        conn = null;
        dbPath = null;
    }
    DatabaseHelpers(String dbPath) {
        this.conn = null;
        this.dbPath = dbPath;
    }
    // Path to DB will look something like "jdbc:sqlite:PATH_TO_DB"

    /**
     * Establishes a JDBC Connection to the SQLite3 Database
     * @throws SQLException
     */
    private void connectToDb() throws SQLException{
        System.out.println("In connectToDb");
        try {
            if (this.dbPath == null) {
                Exception e = new RuntimeException("dbPath for this instance is not specified.");
                throw e;
            }
            else if (this.conn != null) {
                System.out.println("Connection already established.");
                return;
            }
            this.conn = DriverManager.getConnection(this.dbPath);
            System.out.println("Connection established. Set to instance-owned connection.");
        }
        catch (Exception e) {
            if (e instanceof SQLException){
                System.err.println("Connection to database could not be established. SQLException triggered");
                System.err.println(e.getMessage());
            }
            else {
                System.err.println("Connection to database could not be established. Database Path is incorrect/Not Set");
            }
            e.printStackTrace();
        }
    }

    /**
     * Closes the JDBC Connection, if it is connected at runtime.
     */
    private void closeDbConnection() {
        System.out.println("In closeDbConnection");
        try {
            if(this.conn != null) {
                this.conn.close();
            }
            else {
                System.out.println("Connection already closed.");
                return;
            }
        }
        catch (SQLException e) {
            System.err.println("Error Code : " + e.getErrorCode());
            System.err.println("SQL State : " + e.getSQLState());
            System.err.println(e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Sets the path for the database to be used in JDBC connection. Acts OS-agnostic (but not tested on that note).
     * @param databaseName
     */
    private void setDatabasePath (String databaseName) {
        System.out.println("In setDatabasePath");
        //Setting instance dbName to filepath
        if (this.dbPath == null) {
            String currentWorkingDir = FileSystems.getDefault().getPath("").toAbsolutePath().toString();
            String filePath = String.format("jdbc:sqlite:%s", currentWorkingDir) + String.format("/%s", databaseName) + ".sqlite";
            this.dbPath = filePath;
        }
        else {
            System.out.println("Path already set.");
            return;
        }
    }

    /**
     * Creates a new Database (and generates a new .sqlite file due to it) with preset name and parameters.
     * @param databaseName
     * @param tableName
     */
    public void createNewDatabase(String databaseName, String tableName) {
        System.out.println("In createNewDatabase");
        setDatabasePath(databaseName);
        try {
            connectToDb();
            if (this.conn != null) {
                DatabaseMetaData metadata = this.conn.getMetaData();
                System.out.println("Driver details: \n" + metadata.getDriverName() + "\n" + metadata.getDriverVersion());
                System.out.println("Database created successfully.");
                createTable(databaseName, tableName);
            }
        }
        catch (SQLException e) {
            System.err.println("Error Code : " + e.getErrorCode());
            System.err.println("SQL State : " + e.getSQLState());
            System.err.println(e.getMessage());
            e.printStackTrace();
            closeDbConnection();
        }
        catch (Exception e) {
            System.err.println("Database could not be created.");
            e.printStackTrace();
            closeDbConnection();
        }
    }
    
    /**
     * Creates a table in the active Database present and connected. 
     * @param databaseName
     * @param tableName
     */
    public void createTable(String databaseName, String tableName) {
        System.out.println("In createTable");
        setDatabasePath(databaseName);
        String sqlCreateStatement = String.format("CREATE TABLE IF NOT EXISTS %s (\n", tableName) +
         "  uid text PRIMARY KEY, \n" + 
         "  rsapublickey text NOT NULL, \n" + 
         "  rsaprivatekey text NOT NULL\n" + 
         ");";
        try {
            connectToDb();
            if (this.conn != null){
                Statement statement = conn.createStatement();
                statement.execute(sqlCreateStatement);
                System.out.println("Success");
            }
        }
        catch (SQLException e) {
            System.err.println("Error Code : " + e.getErrorCode());
            System.err.println("SQL State : " + e.getSQLState());
            System.err.println(e.getMessage());
            e.printStackTrace();
            closeDbConnection();
        }
        catch (Exception e) {
            System.err.println("Table could not be created.");
            e.printStackTrace();
            closeDbConnection();
        }
        
    }

    /**
     * Used to insert RSA-2048 keys into Database. Will check if any old keys exist. If they do, the keys will be updated. If no old keys exist against 
     * that UID, they will be added.
     * @param databaseName
     * @param tableName
     * @param uid
     * @param rsaPublicKey
     * @param rsaPrivateKey
     */
    public void insertKeysToDatabase(String databaseName, String tableName, String uid, PublicKey rsaPublicKey, PrivateKey rsaPrivateKey) {
        System.out.println("In insertKeysToDatabase");
        setDatabasePath(databaseName);
        String sqlInsertDataStatement = String.format("INSERT INTO %s (uid, rsapublicKey, rsaprivateKey) VALUES (?,?,?)", tableName);

        Map<String, byte[]> keysLoaded = readKeysFromDatabase(databaseName, tableName, uid);
        if(keysLoaded.get("PrivateKey") != null || keysLoaded.get("PublicKey") != null) {
            updateKeysInDatabase(databaseName, tableName, uid, rsaPublicKey, rsaPrivateKey);
            return;
        }
        System.out.println("\n\nCrossed update \n\n");
        // if uid has already got keys associated, update the keys instead of inserting
        try{
            connectToDb();
            System.out.println("\n\nCrossed connect \n\n");
            PreparedStatement statement = this.conn.prepareStatement(sqlInsertDataStatement);
            connectToDb();
            byte[] publicKeyBytes = rsaPublicKey.getEncoded();
            byte[] privateKeyBytes = rsaPrivateKey.getEncoded();
            String publicKeyStringDerivedFromBytes = Hex.encodeHexString(publicKeyBytes);
            String privateKeyStringDerivedFromBytes = Hex.encodeHexString(privateKeyBytes);
            statement.setString(1, uid);
            statement.setString(2, publicKeyStringDerivedFromBytes);
            statement.setString(3, privateKeyStringDerivedFromBytes);
            statement.executeUpdate();
            System.out.println("\n\nCrossed executeupdate \n\n");
            System.out.println("Keys saved.");
        }
        catch (SQLException e) {
            System.err.println("Error Code : " + e.getErrorCode());
            System.err.println("SQL State : " + e.getSQLState());
            System.err.println(e.getMessage());
            if (e.getMessage().contains("no such table: key_data")) {
                System.err.println("Creating table reached");
                createTable(databaseName, tableName);
                insertKeysToDatabase(databaseName, tableName, uid, rsaPublicKey, rsaPrivateKey);
                return;
            }
            e.printStackTrace();
        }
        catch (Exception e) {
            System.err.println("Keys were not set.");
            e.printStackTrace();
        }
    }

    // WARNING : CAN RETURN NULL VALUES. RETURNS DECODED HEX STRING IN BYTE ARRAY FORMAT

    /**
     * Query and read RSA-2048 keys from the Database. It keeps a track of both Private and Public keys, so it returns both. Requires UID for internal functions
     * @param databaseName
     * @param tableName
     * @param uid
     * @return Map &lt String, byte[] &gt
     */
    public Map<String, byte[]> readKeysFromDatabase(String databaseName, String tableName, String uid) {
        System.out.println("In readKeysFromDatabase");
        setDatabasePath(databaseName);
        Map<String, byte[]> cryptographicRsaKeys = new HashMap<String, byte[]>();
        cryptographicRsaKeys.put("PrivateKey", null);
        cryptographicRsaKeys.put("PublicKey", null);
        try {
            connectToDb();
            String queryFromTableStatement = String.format("SELECT uid, rsapublickey, rsaprivatekey FROM %s WHERE uid=?", tableName);
            PreparedStatement statement = this.conn.prepareStatement(queryFromTableStatement);
            connectToDb();
            statement.setString(1, uid);
            ResultSet resultSet = statement.executeQuery();
            while(resultSet.next()) {
                cryptographicRsaKeys.put("PrivateKey", Hex.decodeHex(resultSet.getString("rsaprivatekey")));
                cryptographicRsaKeys.put("PublicKey", Hex.decodeHex(resultSet.getString("rsapublickey")));
            }
            if((cryptographicRsaKeys.get("PrivateKey") != null) && (cryptographicRsaKeys.get("PublicKey") != null)) {
                return cryptographicRsaKeys;
            }
            else {
                Exception e = new RuntimeException("KeysNotSet");
                throw e;
            }
        }
        catch (SQLException e) {
            System.err.println("Error Code : " + e.getErrorCode());
            System.err.println("SQL State : " + e.getSQLState());
            System.err.println(e.getMessage());
            e.printStackTrace();
            if (conn != null) {
                // closeDbConnection();
            }
        }
        catch (Exception e) {
            if (e.getMessage() == "KeysNotSet") {
                System.err.println("The Keys were either not found or do not exist. Search terminated with no results.");
            }
            else {
                System.err.println(e.getMessage());
            }
            e.printStackTrace();
            if (conn != null) {
                // closeDbConnection();
            }
        }
        return cryptographicRsaKeys;
    }

    /**
     * Update RSA-2048 keys already present in the database against a specific UID. Throws exception if invoked in wrong context.
     * @param databaseName
     * @param tableName
     * @param uid
     * @param rsaPublicKey
     * @param rsaPrivateKey
     */
    public void updateKeysInDatabase(String databaseName, String tableName, String uid, PublicKey rsaPublicKey, PrivateKey rsaPrivateKey) {
        System.out.println("In updateKeysInDatabase");
        setDatabasePath(databaseName);
        try {
            connectToDb();
            Map<String, byte[]> keys = readKeysFromDatabase(databaseName, tableName, uid);
            if ((keys.get("PrivateKey") == null) || (keys.get("PublicKey") == null)) {
                throw new RuntimeException("DataNotFound");
            }
            else {
                String updateStatement = String.format("UPDATE %s SET uid=?, rsapublickey=?, rsaprivatekey=?", tableName); 
                PreparedStatement statement = conn.prepareStatement(updateStatement);
                connectToDb();
                statement.setString(1, uid);
                statement.setString(2, new String(Hex.encodeHex(rsaPublicKey.getEncoded())));
                statement.setString(3, new String(Hex.encodeHex(rsaPrivateKey.getEncoded())));
                statement.executeUpdate();
            }
        }
        catch (SQLException e) {
            System.err.println("Error Code : " + e.getErrorCode());
            System.err.println("SQL State : " + e.getSQLState());
            System.err.println(e.getMessage());
            if (conn != null) {
                closeDbConnection();
            }
            e.printStackTrace();
        }
        catch (Exception e) {
            if (e.getMessage() == "DataNotFound") {
                System.err.println("The requested UID record does not exist.");
            }
            else {
                System.err.println(e.getMessage());
            }
            e.printStackTrace();
            if (conn != null) {
                closeDbConnection();
            }
        }
    }

    /**
     * Deletes a pair of RSA-2048 keys from Database if present against a specific UID. Throws error if invoked in
     * @param databaseName
     * @param tableName
     * @param uid
     */
    public void deleteKeysFromDatabase(String databaseName, String tableName, String uid) {
        System.out.println("In deleteKeysFromDatabase");
        setDatabasePath(databaseName);
        try {
            connectToDb();
            Map<String, byte[]> keys = readKeysFromDatabase(databaseName, tableName, uid);
            if ((keys.get("PrivateKey") == null) || (keys.get("PublicKey") == null)) {
                throw new RuntimeException("DataNotFound");
            }
            else {
                String deleteStatement = String.format("DELETE FROM %s WHERE uid=?", tableName); 
                PreparedStatement statement = conn.prepareStatement(deleteStatement);
                connectToDb();
                statement.setString(1, uid);
                statement.executeUpdate();
            }
        }
        catch (SQLException e) {
            System.err.println("Error Code : " + e.getErrorCode());
            System.err.println("SQL State : " + e.getSQLState());
            System.err.println(e.getMessage());
            e.printStackTrace();
            if (conn != null) {
                closeDbConnection();
            }
        }
        catch (Exception e) {
            if (e.getMessage() == "DataNotFound") {
                System.err.println("The requested UID record does not exist.");
            }
            else {
                System.err.println(e.getMessage());
            }
            e.printStackTrace();
            if (conn != null) {
                closeDbConnection();
            }
        }
    }

}