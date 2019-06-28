package com.eurodyn.encryptionapp.encryption.encryptions;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

public class AESencryptionBc {

    private final BlockCipher AESCipher = new AESEngine();

    private PaddedBufferedBlockCipher pbbc;
    private KeyParameter key;
   // private SecretKey key;

    public AESencryptionBc() throws NoSuchAlgorithmException {

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey sk = kg.generateKey();
        this.key = new KeyParameter(sk.getEncoded());

        this.pbbc = new PaddedBufferedBlockCipher(AESCipher, new PKCS7Padding());
        pbbc.init(true, key);

    }

   /* public void setPadding(BlockCipherPadding bcp) {
        this.pbbc = new PaddedBufferedBlockCipher(AESCipher, bcp);
        pbbc.init(true, key);
       // this.pbbc = new PaddedBufferedBlockCipher(AESCipher);
    } */

   /* public void setKey(byte[] key) {
        this.key = new KeyParameter(key);
    } */

    public byte[] encrypt(byte[] input)
            throws DataLengthException, InvalidCipherTextException {
        return processing(input, true);
    }

    public byte[] decrypt(byte[] input)
            throws DataLengthException, InvalidCipherTextException {
        return processing(input, false);
    }



    private byte[] processing(byte[] input, boolean encrypt)
            throws DataLengthException, InvalidCipherTextException {

        byte[] output = new byte[input.length];

        int bytesWrittenOut = pbbc.processBytes(
                input, 0, input.length, output, 0);
        pbbc.doFinal(output, bytesWrittenOut);

        return output;
    }

}
