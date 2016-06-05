package org.ltj.cryptoeditor.crypto.encryption;

import org.apache.commons.io.IOUtils;
import org.ltj.cryptoeditor.crypto.exception.CryptographyException;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;


public class BCCryptographer implements Cryptographer {


    private final static BCCryptographer instance = new BCCryptographer();
    private final static Charset charset = Charset.forName("ISO-8859-1");


    private BCCryptographer(){}

    public static BCCryptographer getInstance(){
        return instance;
    }

    public String encrypt(String input, Encryption encryption, SecretKey key) throws IOException{
        byte[] bytes = input.getBytes(charset);
        InputStream stream = getEncryptionStream(new ByteArrayInputStream(bytes), encryption, key);
        return streamToString(stream);
    }

    public String encrypt(String input, String password, Encryption encryption) throws Exception{
        char[] pw = password.toCharArray();
        byte[] salt = new byte[]{
                0x7d, 0x60, 0x43, 0x5f,
                0x02, (byte)0xe9, (byte)0xe0, (byte)0xae
        };
        int iterationCount = 2048;
        PBEKeySpec spec = new PBEKeySpec(pw);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWithSHAAnd3KeyTripleDES", "BC");

        Cipher cipher = Cipher.getInstance("PBEWithSHAAnd3KeyTripleDES", "BC");
        Key key = factory.generateSecret(spec);

        cipher.init(Cipher.DECRYPT_MODE,key, new PBEParameterSpec(salt, iterationCount));
        return input;
    }

    public String decrypt(String input, Encryption encryption, SecretKey key) throws IOException{
        byte[] bytes = input.getBytes(charset);
        InputStream stream = getDecryptionStream(new ByteArrayInputStream(bytes), encryption, key);

        return streamToString(stream);
    }

    private String streamToString(InputStream stream) throws IOException{
        return new String(IOUtils.toByteArray(stream),charset);
    }

    private CipherInputStream getEncryptionStream(InputStream in, Encryption encryption, SecretKey key) throws CryptographyException {
        try {
            return new CipherInputStream(in, generateCipher(Cipher.ENCRYPT_MODE, encryption, key));
        } catch (Exception e) {
            throw new CryptographyException(e);
        }
    }

    private CipherInputStream getDecryptionStream(InputStream in, Encryption encryption, SecretKey key) throws CryptographyException {
        try {
            return new CipherInputStream(in, generateCipher(Cipher.DECRYPT_MODE, encryption, key));
        } catch (Exception e) {
            throw new CryptographyException(e);
        }
    }

    private Cipher generateCipher(int cipherMode, Encryption encryption, SecretKey key) throws Exception {
        if (encryption == null) {
            throw new IllegalStateException("BCCryptographer has to be initialized with a valid encryption");
        }
        String transformation = encryption.type.getName();
        if(!encryption.type.isStreamType()) {
            transformation += "/" + encryption.mode.toString();
            transformation += "/" + encryption.options;
        }

        Cipher cipher = Cipher.getInstance(transformation, "BC");

        if(encryption.mode.isVectorMode) {
            if(encryption.getInitializationVector() != null) {
                cipher.init(cipherMode, key, new IvParameterSpec(encryption.getInitializationVector()));
            } else {
                cipher.init(cipherMode, key);
                encryption.setInitializationVector(cipher.getIV());
            }
        } else {
            cipher.init(cipherMode, key);
        }
        return cipher;
    }



}
