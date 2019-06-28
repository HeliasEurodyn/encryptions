package com.eurodyn.encryptionapp.encryption.encryptions;

import java.io.File;
import java.io.FileInputStream;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


public class AESencryption {

   private SecretKeySpec secretKey;
   private Cipher cipherEncryption;
    private Cipher cipherDecryption;


   public AESencryption(String myKey)
    {
        try {
            byte[] randomSalt = new byte[100];
            new Random().nextBytes(randomSalt);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(myKey.toCharArray(), randomSalt, 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            cipherEncryption = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipherEncryption.init(Cipher.ENCRYPT_MODE, secretKey);

            cipherDecryption = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipherDecryption.init(Cipher.DECRYPT_MODE, secretKey);

        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }


    public byte[] encrypt(byte[] dataToEncrypt)
    {
        try
        {
            // return Base64.getEncoder().encode(cipher.doFinal(dataToEncrypt));
            return cipherEncryption.doFinal(dataToEncrypt);
        }
        catch (Exception e)
        {
            e.printStackTrace();
            // System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public void encrypt(ByteBuffer dataToEncrypt, ByteBuffer encryptedData)
    {
        try
        {
            cipherEncryption.doFinal(dataToEncrypt,encryptedData);
        }
        catch (Exception e)
        {
            e.printStackTrace();
            // System.out.println("Error while encrypting: " + e.toString());
        }

    }


    public byte[] decrypt(byte[] dataToDecrypt)
    {
        try
        {
          //  return cipher.doFinal(Base64.getDecoder().decode(dataToDecrypt));
            return cipherDecryption.doFinal(dataToDecrypt);
        }
        catch (Exception e)
        {
            e.printStackTrace();
           // System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }

    public void decrypt(ByteBuffer encryptedData , ByteBuffer decryptedData)
    {
        try
        {
             cipherDecryption.doFinal(encryptedData,decryptedData);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }

    }




}
