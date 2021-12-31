package com.suvaditya.secureDataTransmission;

import java.sql.*;
import java.nio.file.*;
import java.util.*;

import org.apache.commons.codec.binary.Hex;

import java.security.*;

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
    private void connectToDb() throws SQLException{
        System.out.println("In connectToDb");
        try {
            if (this.dbPath == null) {
                Exception e = new Exception("dbPath for this instance is not specified.");
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
    private void setDatabasePath (String databaseName) {
        System.out.println("In setDatabasePath");
        //Setting instance dbName to filepath
        if (this.dbPath == null) {
            String currentWorkingDir = FileSystems.getDefault().getPath("").toAbsolutePath().toString();
            System.out.println(currentWorkingDir);
            String filePath = String.format("jdbc:sqlite:%s", currentWorkingDir) + String.format("/%s", databaseName) + ".sqlite";
            this.dbPath = filePath;
        }
        else {
            System.out.println("Path already set.");
            return;
        }
    }

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

    public void insertKeysToDatabase(String databaseName, String tableName, String uid, PublicKey rsaPublicKey, PrivateKey rsaPrivateKey) {
        System.out.println("In insertKeysToDatabase");
        setDatabasePath(databaseName);
        System.out.println(this.dbPath);
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
            // closeDbConnection();
        }
        catch (Exception e) {
            System.err.println("Keys were not set.");
            e.printStackTrace();
            // closeDbConnection();
        }
    }

    // WARNING : CAN RETURN NULL VALUES. RETURNS DECODED HEX STRING IN BYTE ARRAY FORMAT
    public Map<String, byte[]> readKeysFromDatabase(String databaseName, String tableName, String uid) {
        System.out.println("In readKeysFromDatabase");
        setDatabasePath(databaseName);
        Map<String, byte[]> cryptographicRsaKeys = new HashMap<String, byte[]>();
        cryptographicRsaKeys.put("PrivateKey", null);
        cryptographicRsaKeys.put("PublicKey", null);
        try {
            connectToDb();
            String queryFromTableStatement = String.format("SELECT uid, rsapublickey, rsaprivatekey FROM %s WHERE uid=?", tableName);
            System.out.println(queryFromTableStatement);
            PreparedStatement statement = this.conn.prepareStatement(queryFromTableStatement);
            connectToDb();
            statement.setString(1, uid);
            ResultSet resultSet = statement.executeQuery();
            while(resultSet.next()) {
                // cryptographicRsaKeys.put("PrivateKey", resultSet.getBinaryStream("rsaprivatekey").readAllBytes().toString().getBytes());
                // cryptographicRsaKeys.put("PublicKey", resultSet.getBinaryStream("rsapublickey").readAllBytes().toString().getBytes());
                cryptographicRsaKeys.put("PrivateKey", Hex.decodeHex(resultSet.getString("rsaprivatekey")));
                cryptographicRsaKeys.put("PublicKey", Hex.decodeHex(resultSet.getString("rsapublickey")));
            }
            if((cryptographicRsaKeys.get("PrivateKey") != null) && (cryptographicRsaKeys.get("PublicKey") != null)) {
                System.out.println(cryptographicRsaKeys.get("PrivateKey"));
                System.out.println(cryptographicRsaKeys.get("PublicKey"));
                return cryptographicRsaKeys;
            }
            else {
                Exception e = new Exception("KeysNotSet");
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

    public void updateKeysInDatabase(String databaseName, String tableName, String uid, PublicKey rsaPublicKey, PrivateKey rsaPrivateKey) {
        System.out.println("In updateKeysInDatabase");
        setDatabasePath(databaseName);
        try {
            connectToDb();
            Map<String, byte[]> keys = readKeysFromDatabase(databaseName, tableName, uid);
            if ((keys.get("PrivateKey") == null) || (keys.get("PublicKey") == null)) {
                throw new Exception("DataNotFound");
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

    public void deleteKeysFromDatabase(String databaseName, String tableName, String uid) {
        System.out.println("In deleteKeysFromDatabase");
        setDatabasePath(databaseName);
        try {
            connectToDb();
            Map<String, byte[]> keys = readKeysFromDatabase(databaseName, tableName, uid);
            if ((keys.get("PrivateKey") == null) || (keys.get("PublicKey") == null)) {
                throw new Exception("DataNotFound");
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