package com.suvaditya;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class Base64helpers {
    
    public String encodeString(String data) throws UnsupportedEncodingException {
        try {
            byte[] byteData = data.getBytes("UTF-8");
            String result = Base64.getEncoder().encodeToString(byteData);
            return result;
        }
        catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return e.toString();
        }
    }
    public String decodeString(String cipherString) {
        try {
            byte[] decodedByteData = Base64.getDecoder().decode(cipherString);
            String result = new String(decodedByteData, StandardCharsets.UTF_8);
            return result;
        }
        catch (Exception e) {
            e.printStackTrace();
            return e.toString();
        }
    }
    public String encodeBytes(byte[] data) throws UnsupportedEncodingException {
        try {
            String result = Base64.getEncoder().encodeToString(data);
            return result;
        }
        catch (Exception e) {
            e.printStackTrace();
            return e.toString();
        }
    }
    public String decodeBytes(byte[] encryptedData) {
        try {
            byte[] decodedByteData = Base64.getDecoder().decode(encryptedData);
            String result = new String(decodedByteData, StandardCharsets.UTF_8);
            return result;
        }
        catch (Exception e) {
            e.printStackTrace();
            return e.toString();
        }
    }
    public String encodeURL(String inputURL) throws UnsupportedEncodingException{
        try {
            byte[] byteData = inputURL.getBytes("UTF-8");
            String result = Base64.getUrlEncoder().encodeToString(byteData);
            return result;
        }
        catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return e.toString();
        }
    }
    public String decodeURL(String encodedURL){
        try {
            byte[] decodedByteData = Base64.getUrlDecoder().decode(encodedURL);
            String result = new String(decodedByteData, StandardCharsets.UTF_8);
            return result;
        }
        catch (Exception e) {
            e.printStackTrace();
            return e.toString();
        }
    }
    
}
