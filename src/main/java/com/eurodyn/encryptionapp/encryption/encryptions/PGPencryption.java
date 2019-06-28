package com.eurodyn.encryptionapp.encryption.encryptions;

import java.io.*;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.jcajce.JcaPGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.util.test.UncloseableOutputStream;


public class PGPencryption {

    private int keySize = 2048;

    /*
     * This value should be a Fermat number. 0x10001 (F4) is current recommended value. 3 (F1) is known to be safe also.
     * 3, 5, 17, 257, 65537, 4294967297, 18446744073709551617,
     * <p>
     * Practically speaking, Windows does not tolerate public exponents which do not fit in a 32-bit unsigned integer.
     * Using e=3 or e=65537 works "everywhere".
     * <p>
     * See: <a href="http://stackoverflow.com/questions/11279595/rsa-public-exponent-defaults-to-65537-what-should-this-value-be-what-are-the">stackoverflow: RSA Public exponent defaults to 65537. ... What are the impacts of my choices?</a>
     */
    private BigInteger publicExponent = BigInteger.valueOf(0x10001);

    /*
     * How certain do we want to be that the chosen primes are really primes.
     * <p>
     * The higher this number, the more tests are done to make sure they are primes (and not composites).
     * <p>
     * See: <a href="http://crypto.stackexchange.com/questions/3114/what-is-the-correct-value-for-certainty-in-rsa-key-pair-generation">What is the correct value for “certainty” in RSA key pair generation?</a>
     * and
     * <a href="http://crypto.stackexchange.com/questions/3126/does-a-high-exponent-compensate-for-a-low-degree-of-certainty?lq=1">Does a high exponent compensate for a low degree of certainty?</a>
     */
    private int certainty = 12;

    private int symmetricAlgorithm = PGPEncryptedData.AES_128;


    public void setKeySize(int keySize) {
        this.keySize = keySize;
    }

    public void setPublicExponent(BigInteger publicExponent) {
        this.publicExponent = publicExponent;
    }

    public void setCertainty(int certainty) {
        this.certainty = certainty;
    }

    public void setSymmetricAlgorithm(int symmetricAlgorithm) {
        this.symmetricAlgorithm = symmetricAlgorithm;
    }


    /**
     *  Reads a public key from a File to use it for the encryption process.
     *  Reads data from an input File, encrypts them and saves them to an output File.
     *
     * @param inputFile Is the file to read the data to be encrypted
     * @param outputFile Is the file to write the encrypted data
     * @param publicKeyFile Is the file to read the public key for the encryption process
     *
     * @throws IOException
     * @throws PGPException
     */
    public void encrypt( File inputFile, File outputFile, File publicKeyFile) throws IOException, PGPException {
        PGPPublicKeyRing publicKeyRing = this.readPublicKeyFromFile(publicKeyFile);
        this.encrypt(inputFile, outputFile, publicKeyRing);
    }

    /**
     * Reads data from an input File, encrypts them and saves them to an output File
     * using the publickeyByteArray.
     *
     * @param inputFile Is the file to read the data to be encrypted
     * @param outputFile Is the file to write the encrypted data
     * @param publicKeyBytes Is the public key for the encryption process in byte array
     *
     * @throws IOException
     * @throws PGPException
     */
    public void encrypt( File inputFile, File outputFile, byte[] publicKeyBytes) throws IOException, PGPException {
        PGPPublicKeyRing publicKeyRing = this.createPublicKeyRingFromByteArray(publicKeyBytes);
        this.encrypt(inputFile, outputFile, publicKeyRing);
    }

    /**
     * Reads data from an input File, encrypts them and saves them to an output File
     * using the publicKeyRing.
     *
     * @param inputFile Is the file to read the data to be encrypted
     * @param outputFile Is the file to write the encrypted data
     * @param publicKeyRing Is the encryption public key as an PGPPublicKeyRing Object
     *
     * @throws IOException
     * @throws PGPException
     */
    public void encrypt( File inputFile, File outputFile, PGPPublicKeyRing publicKeyRing)  {

        Iterator<PGPPublicKey> pks = publicKeyRing.getPublicKeys();
        PGPPublicKey encKey = null;

        // get the first encryption key
        while(pks.hasNext()){
            PGPPublicKey pk = pks.next();
            if (pk.isEncryptionKey()){
                encKey = pk;
                break;
            }
        }

        encryptFile(inputFile,outputFile, encKey, this.symmetricAlgorithm);
    }



    /**
     *  Reads a public key from a File to use it for the encryption process.
     *  Encrypts the dataToEncrypt byte array and returns the encrypted byte array.
     *
     * @param dataToEncrypt Is a byte array of the data to be encrypted
     * @param publicKeyFile Is the file to read the public key for the encryption process
     *
     * @return a byte array of the encrypted data
     *
     * @throws IOException
     * @throws PGPException
     */
    public byte[] encrypt( byte[] dataToEncrypt, File publicKeyFile) throws IOException, PGPException {

        PGPPublicKeyRing publicKeyRing = this.readPublicKeyFromFile(publicKeyFile);
        return encrypt(dataToEncrypt, publicKeyRing);
    }

    /**
     * Encrypts the dataToEncrypt byte array and returns the encrypted byte array.
     *
     * @param dataToEncrypt Is a byte array of the data to be encrypted
     * @param publicKeyBytes Is the public key for the encryption process in byte array
     *
     * @return a byte array of the encrypted data
     *
     * @throws IOException
     * @throws PGPException
     */
    public byte[] encrypt( byte[] dataToEncrypt, byte[] publicKeyBytes) throws IOException, PGPException {

        PGPPublicKeyRing publicKeyRing = this.createPublicKeyRingFromByteArray(publicKeyBytes);
        return encrypt(dataToEncrypt, publicKeyRing);

    }

    /**
     * Encrypts the dataToEncrypt byte array and returns the encrypted byte array.
     *
     * @param dataToEncrypt Is a byte array of the data to be encrypted
     * @param publicKeyRing Is the encryption public key as an PGPPublicKeyRing Object
     *
     * @return a byte array of the encrypted data
     *
     * @throws IOException
     * @throws PGPException
     */
    public byte[] encrypt( byte[] dataToEncrypt, PGPPublicKeyRing publicKeyRing)  {

            Iterator<PGPPublicKey> pks = publicKeyRing.getPublicKeys();
            PGPPublicKey encKey = null;

            // get the first encryption key
            while(pks.hasNext()){
                PGPPublicKey pk = pks.next();
                if (pk.isEncryptionKey()){
                    encKey = pk;
                    break;
                }
            }

            // encrypt
            return encryptData(dataToEncrypt, encKey, this.symmetricAlgorithm);
        }



    /**
     *  Reads a private key from a File to use it for the decryption process.
     *  Reads encrypted data from an input File, dencrypts them and returns the decrypted data filestream.
     *
     * @param inputFile Is the file to read the data to be encrypted
     * @param privateKeyFile Is the file to read the private key for the decryption process
     * @param pass is the decryption password
     *
     * @return Returns the decrypted data InputStream
     *
     * @throws IOException
     * @throws PGPException
     */
    public InputStream decrypt(File inputFile, File privateKeyFile, char[] pass) throws IOException, PGPException {
        PGPSecretKeyRing privateKeyRing = this.readPrivateKeyFromFile(privateKeyFile);
        return this.decrypt(inputFile, privateKeyRing, pass);
    }

    /**
     *  Reads encrypted data from an input File, dencrypts them and returns the decrypted data filestream.
     *
     * @param inputFile Is the file to read the data to be encrypted
     * @param privateKeyBytes Is the private key byte array for the decryption process
     * @param pass is the decryption password
     *
     * @return Returns the decrypted data InputStream
     *
     * @throws IOException
     * @throws PGPException
     */
    public InputStream decrypt(File inputFile, byte[] privateKeyBytes, char[] pass) throws IOException, PGPException {
        PGPSecretKeyRing privateKeyRing = this.createPrivateKeyRingFromByteArray(privateKeyBytes);
        return this.decrypt(inputFile, privateKeyRing, pass);
    }

    /**
     *  Reads encrypted data from an input File, dencrypts them and returns the decrypted data filestream.
     *
     * @param inputFile Is the file to read the data to be encrypted
     * @param privateKeyRing Is the private key PGPSecretKeyRing Object for the decryption process
     * @param pass is the decryption password
     *
     * @return Returns the decrypted data InputStream
     *
     * @throws IOException
     * @throws PGPException
     */
    public InputStream decrypt(File inputFile, PGPSecretKeyRing privateKeyRing, char[] pass) throws IOException, PGPException {

        FileInputStream fileInputStream=new FileInputStream(inputFile);
        PGPObjectFactory pgpF = new org.bouncycastle.openpgp.PGPObjectFactory( fileInputStream, new JcaKeyFingerprintCalculator());
        PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpF.nextObject();
        PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);

        //*** Extructs private key using asymetric algorithm
        BcPBESecretKeyDecryptorBuilder decryptorBuilder = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider());
        PGPPrivateKey pgpPrivKey = privateKeyRing.getSecretKey(encP.getKeyID()).extractPrivateKey(decryptorBuilder.build(pass));

        return encP.getDataStream(new BcPublicKeyDataDecryptorFactory(pgpPrivKey));
    }



    /**
     *  Reads a private key from a File to use it for the decryption process.
     *  Dencrypts encryptedDataBytes and returns the decrypted data byte array.
     *
     * @param encryptedDataBytes Is the encrypted data byte array
     * @param privateKeyFile Is the file to read the private key for the decryption process
     * @param pass is the decryption password
     *
     * @return Returns the decrypted data byte array
     *
     * @throws IOException
     * @throws PGPException
     */
    public byte[] decrypt( byte[] encryptedDataBytes, File privateKeyFile, char[] pass) throws IOException, PGPException {
        PGPSecretKeyRing privateKeyRing = this.readPrivateKeyFromFile(privateKeyFile);
        return decrypt( encryptedDataBytes, privateKeyRing, pass);
    }

    /**
     *  Dencrypts encryptedDataBytes and returns the decrypted data byte array.
     *
     * @param encryptedDataBytes Is the encrypted data byte array
     * @param privateKeyBytes Is the private key byte array for the decryption process
     * @param pass is the decryption password
     *
     * @return Returns the decrypted data byte array
     *
     * @throws IOException
     * @throws PGPException
     */
    public byte[] decrypt( byte[] encryptedDataBytes, byte[] privateKeyBytes, char[] pass) throws IOException, PGPException {
        PGPSecretKeyRing privateKeyRing = this.createPrivateKeyRingFromByteArray(privateKeyBytes);
        return decrypt( encryptedDataBytes, privateKeyRing, pass);
    }

    /**
     *  Dencrypts encryptedDataBytes and returns the decrypted data byte array.
     *
     * @param encryptedDataBytes Is the encrypted data byte array
     * @param privateKeyRing Is the private key PGPSecretKeyRing object for the decryption process
     * @param pass is the decryption password
     *
     * @return Returns the decrypted data byte array
     *
     * @throws IOException
     * @throws PGPException
     */
    public byte[] decrypt( byte[] encryptedDataBytes, PGPSecretKeyRing privateKeyRing, char[] pass) throws IOException, PGPException {

            PGPObjectFactory pgpF = new org.bouncycastle.openpgp.PGPObjectFactory(encryptedDataBytes,new JcaKeyFingerprintCalculator());
            PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpF.nextObject();
            PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);

            BcPBESecretKeyDecryptorBuilder decryptorBuilder = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider());
            PGPPrivateKey pgpPrivKey = privateKeyRing.getSecretKey(encP.getKeyID()).extractPrivateKey(decryptorBuilder.build(pass));

            InputStream dataStream = encP.getDataStream(new BcPublicKeyDataDecryptorFactory(pgpPrivKey));

            return dataStream.readAllBytes();

    }


    /**
     * Generates private and public key pair and saves them to files
     *
     * @param privateKeyFile The file for the private key to be saved
     * @param publicKeyFile The file for the public key to be saved
     * @param user The username for the keys to be generated
     * @param pass The password for the keys to be generated
     *
     * @return The PGPKeyRingGenerator that contains the new public-private key pair
     *
     * @throws IOException
     */
    public PGPKeyRingGenerator generateKeys(File privateKeyFile, File publicKeyFile, String user, char[] pass) throws IOException {
        PGPKeyRingGenerator rsaKr = this.generateKeys( user, pass);
        this.saveKeysToFile( rsaKr,  privateKeyFile,  publicKeyFile);
        return rsaKr;
    }

    /**
     * Generates private and public key pair
     *
     * @param user The username for the keys to be generated
     * @param pass The password for the keys to be generated
     *
     * @return The PGPKeyRingGenerator that contains the new public-private key pair
     *
     * @throws IOException
     */
    public PGPKeyRingGenerator generateKeys(String user, char[] pass) {

            try {

            // This object generates individual key-pairs.
            RSAKeyPairGenerator kpg = new RSAKeyPairGenerator();
            PGPKeyRingGenerator rsaKr = null;

            // Boilerplate RSA parameters, no need to change anything
            // except for the RSA key-size (2048). You can use whatever key-size
            // makes sense for you -- 4096, etc.
            RSAKeyGenerationParameters rsaKeyGenerationParameters = new RSAKeyGenerationParameters(publicExponent, new SecureRandom(), keySize, certainty);
            kpg.init(rsaKeyGenerationParameters);

            // First create the master (signing) key with the generator.
            PGPKeyPair kpSign = new BcPGPKeyPair(PGPPublicKey.RSA_SIGN, kpg.generateKeyPair(), new Date());
            // Then an encryption subkey.
            PGPKeyPair kpEnc = new BcPGPKeyPair(PGPPublicKey.RSA_ENCRYPT, kpg.generateKeyPair(), new Date());

            // Sign the master key packet
            // Add a self-signature on the id
            PGPSignatureSubpacketGenerator signSigPacket = new PGPSignatureSubpacketGenerator();

            // Add signed metadata on the (master key) signature.
            // 1) Declare its purpose
            boolean isCritical = true;
            int keyPurpose = KeyFlags.SIGN_DATA | KeyFlags.CERTIFY_OTHER;
            signSigPacket.setKeyFlags(isCritical, keyPurpose);


             // Set preferences for secondary crypto algorithms to use when
             // sending messages to this key.
            int[] symAlgos = new int[] {SymmetricKeyAlgorithmTags.AES_256,SymmetricKeyAlgorithmTags.AES_128,  SymmetricKeyAlgorithmTags.AES_192, SymmetricKeyAlgorithmTags.BLOWFISH, SymmetricKeyAlgorithmTags.CAST5};
            signSigPacket.setPreferredSymmetricAlgorithms(isCritical, symAlgos);

            int[] hashAlgos = new int[] {HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA384, HashAlgorithmTags.SHA256};
            signSigPacket.setPreferredHashAlgorithms(isCritical, hashAlgos);


            // sign encryption subkey
            // Create a signature on the encryption subkey.
            PGPSignatureSubpacketGenerator signEncPacket = new PGPSignatureSubpacketGenerator();

            // Add metadata to declare its purpose
            keyPurpose = KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE;
            signEncPacket.setKeyFlags(isCritical, keyPurpose);


            // digests
            // Objects used to encrypt the secret key.
            PGPDigestCalculator digest1 = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1);
            PGPDigestCalculator digest256 = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA256);

            // encryption for secret key
            // bcpg 1.48 exposes this API that includes s2kcount. Earlier versions
            // use a default of 0x60.
            PBESecretKeyEncryptor pske = (new BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, digest256, 100)).build(pass);

           // Finally, create the keyring itself. The constructor takes parameters
           // that allow it to generate the self signature.
            BcPGPContentSignerBuilder contentSignerBuilder = new BcPGPContentSignerBuilder(kpSign.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256);
            rsaKr = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, kpSign, user, digest1, signSigPacket.generate(), null, contentSignerBuilder, pske);

            // Add our encryption subkey, together with its signature.
            rsaKr.addSubKey(kpEnc, signEncPacket.generate(), null);

          return rsaKr;

        } catch (PGPException e){
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Reads the public key from file and returns the PGPPublicKeyRing Object
     *
     * @param path The path where the public key is saved
     *
     * @return The PGPPublicKeyRing that contains the public key
     *
     * @throws IOException
     */
    public PGPPublicKeyRing readPublicKeyFromFile(File path) throws IOException, PGPException {
        InputStream in = new BufferedInputStream(new FileInputStream(path));
        in = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(in);
        JcaPGPPublicKeyRingCollection pgpPub = new JcaPGPPublicKeyRingCollection(in);
        in.close();
        Iterator<PGPPublicKeyRing> rIt = pgpPub.getKeyRings();

        while (rIt.hasNext())
        {
            return rIt.next();
        }

        return null;
    }

    /**
     * Reads the private key from file and returns the PGPSecretKeyRing Object
     *
     * @param path The path where the private key is saved
     *
     * @return The PGPSecretKeyRing that contains the private key
     *
     * @throws IOException
     */
    public PGPSecretKeyRing readPrivateKeyFromFile(File path) throws IOException, PGPException {

        InputStream in = new BufferedInputStream(new FileInputStream(path));
        in = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(in);
        JcaPGPSecretKeyRingCollection pgpPri = new JcaPGPSecretKeyRingCollection(in);
        in.close();
        Iterator<PGPSecretKeyRing> rIt = pgpPri.getKeyRings();

        while (rIt.hasNext()) {
            return rIt.next();
        }
        return null;

    }

    /**
     * Saves private-public key pair to files
     *
     * @param rsaKr The PGPKeyRingGenerator Object that contains the private-public key pair
     * @param privateKeyFile The file for the private key to be saved
     * @param publicKeyFile The file for the public key to be save
     *
     * @throws IOException
     */
    public void saveKeysToFile(PGPKeyRingGenerator rsaKr, File privateKeyFile, File publicKeyFile) throws IOException {
        BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(publicKeyFile));
        rsaKr.generatePublicKeyRing().encode(out);
        out.close();

        out = new BufferedOutputStream(new FileOutputStream(privateKeyFile));
        rsaKr.generateSecretKeyRing().encode(out);
        out.close();
    }

    /**
     * Saves public key to File
     *
     * @param publicKeyRing The PGPPublicKeyRing Object that contains the public key
     * @param publicKeyFile The File for the public key to be saved
     *
     * @throws IOException
     */
    public void savePublicKeyRing(PGPPublicKeyRing publicKeyRing, File publicKeyFile) throws IOException {
        BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(publicKeyFile));
        publicKeyRing.encode(out);
        out.close();
    }

    /**
     * Saves private key to File
     *
     * @param privateKeyRing The PGPSecretKeyRing Object that contains the private key
     * @param privateKeyFile The File for the privated key to be saved
     *
     * @throws IOException
     */
    public void savePrivateKeyRing(PGPSecretKeyRing privateKeyRing, File privateKeyFile) throws IOException {
        BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(privateKeyFile));
        privateKeyRing.encode(out);
        out.close();
    }

    /**
     * Converts byte[] to PGPPublicKeyRing
     *
     * @param keyBytes Public key to byte[]
     *
     * @return  Public key to PGPPublicKeyRing Object
     *
     * @throws IOException
     */
    public PGPPublicKeyRing createPublicKeyRingFromByteArray(byte[] keyBytes) throws IOException, PGPException {

        InputStream in = new ByteArrayInputStream(keyBytes);
        in = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(in);
        JcaPGPPublicKeyRingCollection pgpPub = new JcaPGPPublicKeyRingCollection(in);
        in.close();
        Iterator<PGPPublicKeyRing> rIt = pgpPub.getKeyRings();

        while (rIt.hasNext())
        {
            return rIt.next();
        }

        return null;
    }

    /**
     * Converts byte[] to PGPSecretKeyRing
     *
     * @param keyBytes private key as a byte[]
     *
     * @return  Private key as a PGPSecretKeyRing Object
     *
     */
    public PGPSecretKeyRing createPrivateKeyRingFromByteArray(byte[] keyBytes) throws IOException, PGPException {

        InputStream in = new ByteArrayInputStream(keyBytes);
        in = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(in);
        JcaPGPSecretKeyRingCollection pgpPri = new JcaPGPSecretKeyRingCollection(in);
        in.close();
        Iterator<PGPSecretKeyRing> rIt = pgpPri.getKeyRings();

        while (rIt.hasNext()) {
            return rIt.next();
        }
        return null;
    }


    private byte[] encryptData(byte[] bytesToEncrypt, PGPPublicKey encKey, int symAlgo){
        try {

            PGPDataEncryptorBuilder encBuilder = new BcPGPDataEncryptorBuilder(symAlgo).setWithIntegrityPacket(true);
            PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(encBuilder);

            encGen.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(encKey));

            ByteArrayOutputStream baOut = new ByteArrayOutputStream();
            OutputStream cOut = encGen.open(new UncloseableOutputStream(baOut), bytesToEncrypt.length);
            cOut.write(bytesToEncrypt);
            cOut.close();

            return baOut.toByteArray();

        } catch (PGPException|IOException e) {
            e.printStackTrace();
        }

        return new byte[0];
    }

    private void encryptFile(File inputFile,File outputFile,  PGPPublicKey encKey, int symAlgo){
        try {

            PGPDataEncryptorBuilder encBuilder = new BcPGPDataEncryptorBuilder(symAlgo).setWithIntegrityPacket(true);
            PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(encBuilder);

            encGen.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(encKey));

            try(
            OutputStream outputStream = new FileOutputStream(outputFile);
            FileInputStream fileInputStream=new FileInputStream(inputFile);
            OutputStream encOutputStream = encGen.open(new UncloseableOutputStream(outputStream), inputFile.length() );
                ) {

                    byte[] buffer = new byte[1024];
                    int len = fileInputStream.read(buffer);
                    while (len != -1) {
                        encOutputStream.write(buffer, 0, len);
                        len = fileInputStream.read(buffer);
                    }

                }

            } catch (PGPException | IOException e  ) {
                e.printStackTrace();
            }

    }












}
