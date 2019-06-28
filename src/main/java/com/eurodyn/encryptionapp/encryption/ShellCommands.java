package com.eurodyn.encryptionapp.encryption;

//import org.bouncycastle.crypto.paddings
import java.io.*;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.*;

import com.eurodyn.encryptionapp.encryption.encryptions.AESencryption;
import com.eurodyn.encryptionapp.encryption.encryptions.AESencryptionBc;
import com.eurodyn.encryptionapp.encryption.encryptions.PGPencryption;
import com.eurodyn.encryptionapp.encryption.encryptions.RSAencryption;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.openpgp.*;
import org.springframework.shell.standard.ShellComponent;
import org.springframework.shell.standard.ShellMethod;
import org.springframework.shell.standard.ShellOption;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;


@ShellComponent
public class ShellCommands {


    int datasize = 100;
    boolean detailResults = true;


    @ShellMethod("set data size for the encrytion tests")
    public void datasize(
            @ShellOption int datasize)  {
            this.datasize = datasize;
    }

    @ShellMethod("set detailResults display on not")
    public void detailresults(
            @ShellOption boolean detailResults)  {
        this.detailResults = detailResults;
    }


    @ShellMethod("PgpEncryption - encryption execution time")
    public void pgpencryption_loop(
            @ShellOption int total
    ) throws IOException, PGPException, InvalidCipherTextException, NoSuchAlgorithmException {
        long totalTime = 0;
        for(int i=0; i<total; i++) totalTime += this.pgpencryption();

        System.out.println("");
        System.out.println("*** Total Encryptions: " + total);
        System.out.println("*** Data size on each encryption: " + this.datasize);
        System.out.println("*** Total time msecs: " + totalTime/ 1000000.0);
    }

    @ShellMethod("PgpEncryption - encryption execution time")
    public long pgpencryption() throws IOException, PGPException {

        File publicKeyFile = new File("pgpPublicKeyRing.pkr");
        File privateKeyFile = new File("pgpSecretKeyRing.skr");
        PGPencryption pgpEnc = new PGPencryption();
        PGPPublicKeyRing publicKey = pgpEnc.readPublicKeyFromFile(publicKeyFile);
        PGPSecretKeyRing privateKey = pgpEnc.readPrivateKeyFromFile(privateKeyFile);

        byte[] dataToEncrypt = new byte[this.datasize];
        new Random().nextBytes(dataToEncrypt);

        long start = System.nanoTime();
        byte[] dataEncrypted = pgpEnc.encrypt(dataToEncrypt,publicKey);
        long time = System.nanoTime() - start;

        if(this.detailResults) System.out.println(  time / 1000000.0 );
        return time;
    }




    @ShellMethod("PgpEncryption - decryption execution time")
    public void pgpencryptiond_loop(
            @ShellOption int total
    ) throws IOException, PGPException {
        long totalTime = 0;
        for(int i=0; i<total; i++) totalTime += this.pgpencryptiond();

        System.out.println("");
        System.out.println("*** Total Encryptions: " + total);
        System.out.println("*** Data size on each encryption: " + this.datasize);
        System.out.println("*** Total time msecs: " + totalTime/ 1000000.0);
    }

    @ShellMethod("PgpEncryption - decryption execution time")
    public long pgpencryptiond() throws IOException, PGPException {

        File publicKeyFile = new File("pgpPublicKeyRing.pkr");
        File privateKeyFile = new File("pgpSecretKeyRing.skr");
        PGPencryption pgpEnc = new PGPencryption();
        PGPPublicKeyRing publicKey = pgpEnc.readPublicKeyFromFile(publicKeyFile);
        PGPSecretKeyRing privateKey = pgpEnc.readPrivateKeyFromFile(privateKeyFile);

        byte[] dataToEncrypt = new byte[this.datasize];
        new Random().nextBytes(dataToEncrypt);

        byte[] encryptedData = pgpEnc.encrypt(dataToEncrypt,publicKey);

        long start = System.nanoTime();
            byte[] decryptedData = pgpEnc.decrypt(encryptedData,privateKey, "123456".toCharArray());
        long time = System.nanoTime() - start;

        if(this.detailResults) System.out.println(  time / 1000000.0 );
        return time;
    }





    @ShellMethod("AESEncryptionBC - encryption execution time")
    public void aesencryptionbc_loop(
            @ShellOption int total
    ) throws InvalidCipherTextException, NoSuchAlgorithmException {
        long totalTime = 0;
        for(int i=0; i<total; i++) totalTime +=  this.aesencryptionbc();

        System.out.println("");
        System.out.println("*** Total Encryptions: " + total);
        System.out.println("*** Data size on each encryption: " + this.datasize);
        System.out.println("*** Total time msecs: " + totalTime/ 1000000.0);
    }

    @ShellMethod("AESEncryptionBC - encryption execution time")
    public long aesencryptionbc() throws NoSuchAlgorithmException, InvalidCipherTextException {

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey sk = kg.generateKey();

        AESencryptionBc aESEncryption = new AESencryptionBc();
        //aESEncryption.setKey(sk.getEncoded());
       // aESEncryption.setPadding(new PKCS7Padding());

        byte[] dataToEncrypt = new byte[this.datasize];
        new Random().nextBytes(dataToEncrypt);

        long start = System.nanoTime();
            byte[] encr = aESEncryption.encrypt(dataToEncrypt);
        long time = System.nanoTime() - start;
        if(this.detailResults) System.out.println(  time / 1000000.0 );
        return time;
    }




    @ShellMethod("AESEncryptionBC - decryption execution time")
    public void aesencryptionbcd_loop(
            @ShellOption int total
    ) throws  InvalidCipherTextException, NoSuchAlgorithmException {
        long totalTime = 0;
        for(int i=0; i<total; i++) totalTime += this.aesencryptionbcd();

        System.out.println("");
        System.out.println("*** Total Encryptions: " + total);
        System.out.println("*** Data size on each encryption: " + this.datasize);
        System.out.println("*** Total time msecs: " + totalTime/ 1000000.0);
    }

    @ShellMethod("AESEncryptionBC - decryption execution time")
    public long aesencryptionbcd() throws NoSuchAlgorithmException, InvalidCipherTextException {

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey sk = kg.generateKey();
        AESencryptionBc aESEncryption = new AESencryptionBc();
      //  aESEncryption.setKey(sk.getEncoded());
      //  aESEncryption.setPadding(new PKCS7Padding());

        byte[] dataToEncrypt = new byte[this.datasize];
        new Random().nextBytes(dataToEncrypt);
        byte[] encryptedData = aESEncryption.encrypt(dataToEncrypt);

        long start = System.nanoTime();
        byte[] decryptedData = aESEncryption.encrypt(encryptedData);
        long time = System.nanoTime() - start;

        if(this.detailResults) System.out.println(  time / 1000000.0 );
        return time;
    }





    @ShellMethod("AESEncryption - encryption execution time")
    public void aesencryption_loop(
            @ShellOption int total
    ) throws IOException, PGPException, InvalidCipherTextException, NoSuchAlgorithmException {
        long totalTime = 0;
        for(int i=0; i<total; i++) totalTime += this.aesencryption();

        System.out.println("");
        System.out.println("*** Total Encryptions: " + total);
        System.out.println("*** Data size on each encryption: " + this.datasize);
        System.out.println("*** Total time msecs: " + totalTime/ 1000000.0);
    }

    @ShellMethod("AESEncryption - encryption execution time")
    public long aesencryption() throws IOException, PGPException, NoSuchAlgorithmException, InvalidCipherTextException {

        byte[] dataToEncrypt = new byte[this.datasize];
        new Random().nextBytes(dataToEncrypt);

        final String secretKey = "ssshhhhhhhhhhh!!!!";
        AESencryption aesJava = new AESencryption(secretKey);

        long start = System.nanoTime();
            aesJava.encrypt(dataToEncrypt) ;
        long time = System.nanoTime() - start;
        if(this.detailResults)  System.out.println(  time / 1000000.0 );
        return time;
    }




    @ShellMethod("AESEncryption - decryption execution time")
    public void aesencryptiond_loop(
            @ShellOption int total
    ) throws IOException, PGPException, InvalidCipherTextException, NoSuchAlgorithmException {
        long totalTime = 0;
        for(int i=0; i<total; i++) totalTime += this.aesencryptiond();

        System.out.println("");
        System.out.println("*** Total Encryptions: " + total);
        System.out.println("*** Data size on each encryption: " + this.datasize);
        System.out.println("*** Total time msecs: " + totalTime/ 1000000.0);
    }

    @ShellMethod("AESEncryption - decryption execution time")
    public long aesencryptiond() throws IOException, PGPException, NoSuchAlgorithmException, InvalidCipherTextException {

        byte[] dataToEncrypt = new byte[this.datasize];
        new Random().nextBytes(dataToEncrypt);

        final String secretKey = "ssshhhhhhhhhhh!!!!";

        AESencryption aesJava = new AESencryption(secretKey);
        byte[] encryptedData =   aesJava.encrypt(dataToEncrypt) ;

        long start = System.nanoTime();
            byte[] decryptedData =   aesJava.decrypt(encryptedData) ;
        long time = System.nanoTime() - start;

        if(this.detailResults) System.out.println(  time / 1000000.0 );

        return time;

    }


    @ShellMethod("RSAEncryption - RSA Algorithm - encryption execution time")
    public void rsaencryption_loop(
            @ShellOption int total
    ) throws Exception {
        long totalTime = 0;
        for(int i=0; i<total; i++) totalTime += this.rsaencryption();

        System.out.println("");
        System.out.println("*** Total Encryptions: " + total);
        System.out.println("*** Data size on each encryption: " + this.datasize);
        System.out.println("*** Total time msecs: " + totalTime/ 1000000.0);
    }


    @ShellMethod("RSAEncryption - RSA Algorithm - encryption execution time")
    public long rsaencryption() throws Exception {
        String publicKeyFilename ="";
        byte[] dataToEncrypt = new byte[this.datasize];
        byte[] encrypted;
        new Random().nextBytes(dataToEncrypt);

        KeyPair keyPair = RSAencryption.generateKey();
        RSAencryption rsAencryption  = new RSAencryption();

        long start = System.nanoTime();
            encrypted = rsAencryption.encrypt(dataToEncrypt, keyPair.getPublic());
        long time = System.nanoTime() - start;

        if(this.detailResults) System.out.println(  time / 1000000.0 );
        return time;
    }


    

    @ShellMethod("Count byte[] random generator exec time")
    public void rgentime() {

        long start = System.nanoTime();
            byte[] dataToEncrypt = new byte[this.datasize];
            new Random().nextBytes(dataToEncrypt);
        long time = System.nanoTime() - start;
        System.out.println(  time / 1000000.0 );

    }



}
