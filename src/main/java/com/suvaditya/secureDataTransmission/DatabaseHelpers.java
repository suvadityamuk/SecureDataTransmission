package com.suvaditya;

import java.sql.*;
import java.nio.file.*;
import java.util.*;
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
                System.out.println("Connection to database could not be established. SQLException triggered");
                System.out.println(e.getMessage());
            }
            else {
                System.out.println("Connection to database could not be established. Database Path is incorrect/Not Set");
            }
            e.printStackTrace();
        }
    }
    private void closeDbConnection() {
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
            System.out.println("Error Code : " + e.getErrorCode());
            System.out.println("SQL State : " + e.getSQLState());
            System.out.println(e.getMessage());
            e.printStackTrace();
        }
    }
    private void setDatabasePath (String databaseName) {
    
        //Setting instance dbName to filepath
        if (this.dbPath == null) {
            String currentWorkingDir = FileSystems.getDefault().getPath("").toAbsolutePath().toString();
            System.out.println(currentWorkingDir);
            String filePath = String.format("jdbc:sqlite:%s", currentWorkingDir) + String.format("/%s", databaseName) + ".db";
            this.dbPath = filePath;
        }
        else {
            System.out.println("Path already set.");
            return;
        }
    }

    public void createNewDatabase(String databaseName) {

        setDatabasePath(databaseName);
        try {
            connectToDb();
            if (this.conn != null) {
                DatabaseMetaData metadata = this.conn.getMetaData();
                System.out.println("Driver details: \n" + metadata.getDriverName() + "\n" + metadata.getDriverVersion());
                System.out.println("Database created successfully.");
            }
        }
        catch (SQLException e) {
            System.out.println("Error Code : " + e.getErrorCode());
            System.out.println("SQL State : " + e.getSQLState());
            System.out.println(e.getMessage());
            e.printStackTrace();
            closeDbConnection();
        }
        catch (Exception e) {
            System.out.println("Database could not be created.");
            e.printStackTrace();
            closeDbConnection();
        }
    }

    public void createTable(String databaseName, String tableName) {

        setDatabasePath(databaseName);
        String sqlCreateStatement = String.format("CREATE TABLE IF NOT EXISTS %s (\n", tableName) +
         "  uid text PRIMARY KEY, \n" + 
         "  rsapublickey BLOB NOT NULL, \n" + 
         "  rsaprivatekey BLOB NOT NULL\n" + 
         ");";
        try {
            connectToDb();
            if (this.conn != null){
                Statement statement = conn.createStatement();
                statement.execute(sqlCreateStatement);
            }
        }
        catch (SQLException e) {
            System.out.println("Error Code : " + e.getErrorCode());
            System.out.println("SQL State : " + e.getSQLState());
            System.out.println(e.getMessage());
            e.printStackTrace();
            closeDbConnection();
        }
        catch (Exception e) {
            System.out.println("Table could not be created.");
            e.printStackTrace();
            closeDbConnection();
        }
        
    }

    public void insertKeysToDatabase(String databaseName, String tableName, String uid, PublicKey rsaPublicKey, PrivateKey rsaPrivateKey) {
        setDatabasePath(databaseName);
        System.out.println(this.dbPath);
        String sqlInsertDataStatement = String.format("INSERT INTO %s (uid, rsapublicKey, rsaprivateKey) VALUES (?,?,?)", tableName);
        try{
            connectToDb();
            PreparedStatement statement = this.conn.prepareStatement(sqlInsertDataStatement);
            statement.setString(1, uid);
            statement.setBytes(2, rsaPublicKey.getEncoded());
            statement.setBytes(3, rsaPrivateKey.getEncoded());
            statement.executeUpdate();
        }
        catch (SQLException e) {
            System.out.println("Error Code : " + e.getErrorCode());
            System.out.println("SQL State : " + e.getSQLState());
            System.out.println(e.getMessage());
            e.printStackTrace();
            closeDbConnection();
        }
        catch (Exception e) {
            System.out.println("Keys were not set.");
            e.printStackTrace();
            closeDbConnection();
        }
    }

    // WARNING : CAN RETURN NULL VALUES
    public Map<String, byte[]> readKeysFromDatabase(String databaseName, String tableName, String uid) {
        setDatabasePath(databaseName);
        Map<String, byte[]> cryptographicRsaKeys = new HashMap<String, byte[]>();
        cryptographicRsaKeys.put("PrivateKey", null);
        cryptographicRsaKeys.put("PublicKey", null);
        try {
            connectToDb();
            String queryFromTableStatement = String.format("SELECT uid, rsapublickey, rsaprivatekey FROM %s WHERE uid=?", tableName);
            PreparedStatement statement = this.conn.prepareStatement(queryFromTableStatement);
            statement.setString(1, uid);
            ResultSet resultSet = statement.executeQuery();
            while(resultSet.next()) {
                cryptographicRsaKeys.put("PrivateKey", resultSet.getBinaryStream("rsaprivatekey").readAllBytes());
                cryptographicRsaKeys.put("PublicKey", resultSet.getBinaryStream("rsapublickey").readAllBytes());
            }
            if((cryptographicRsaKeys.get("PrivateKey") != null) && (cryptographicRsaKeys.get("PublicKey") != null)) {
                return cryptographicRsaKeys;
            }
            else {
                Exception e = new Exception("KeysNotSet");
                throw e;
            }
        }
        catch (SQLException e) {
            System.out.println("Error Code : " + e.getErrorCode());
            System.out.println("SQL State : " + e.getSQLState());
            System.out.println(e.getMessage());
            e.printStackTrace();
            closeDbConnection();
        }
        catch (Exception e) {
            if (e.getMessage() == "KeysNotSet") {
                System.out.println("The Keys were either not found or do not exist. Search terminated with no results.");
            }
            else {
                System.out.println(e.getMessage());
            }
            e.printStackTrace();
            closeDbConnection();
        }
        return cryptographicRsaKeys;
    }

    public void updateKeysInDatabase(String databaseName, String tableName, String uid, PublicKey rsaPublicKey, PrivateKey rsaPrivateKey) {
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
                statement.setString(1, uid);
                statement.setBytes(2, rsaPublicKey.getEncoded());
                statement.setBytes(3, rsaPublicKey.getEncoded());
                statement.executeUpdate();
            }
        }
        catch (SQLException e) {
            System.out.println("Error Code : " + e.getErrorCode());
            System.out.println("SQL State : " + e.getSQLState());
            System.out.println(e.getMessage());
            e.printStackTrace();
        }
        catch (Exception e) {
            if (e.getMessage() == "DataNotFound") {
                System.out.println("The requested UID record does not exist.");
            }
            else {
                System.out.println(e.getMessage());
            }
            e.printStackTrace();
            closeDbConnection();
        }
    }

    public void deleteKeysFromDatabase(String databaseName, String tableName, String uid) {
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
                statement.setString(1, uid);
                statement.executeUpdate();
            }
        }
        catch (SQLException e) {
            System.out.println("Error Code : " + e.getErrorCode());
            System.out.println("SQL State : " + e.getSQLState());
            System.out.println(e.getMessage());
            e.printStackTrace();
            closeDbConnection();
        }
        catch (Exception e) {
            if (e.getMessage() == "DataNotFound") {
                System.out.println("The requested UID record does not exist.");
            }
            else {
                System.out.println(e.getMessage());
            }
            e.printStackTrace();
            closeDbConnection();
        }
    }


    
}
