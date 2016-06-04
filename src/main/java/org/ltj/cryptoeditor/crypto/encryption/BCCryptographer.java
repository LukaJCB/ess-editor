package org.ltj.cryptoeditor.crypto.encryption;

import org.apache.commons.io.IOUtils;
import org.ltj.cryptoeditor.crypto.exception.CryptographyException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;


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
            return new CipherInputStream(in, buildCipher(Cipher.ENCRYPT_MODE, encryption, key));
        } catch (Exception e) {
            throw new CryptographyException(e);
        }
    }

    private CipherInputStream getDecryptionStream(InputStream in, Encryption encryption, SecretKey key) throws CryptographyException {
        try {
            return new CipherInputStream(in, buildCipher(Cipher.DECRYPT_MODE, encryption, key));
        } catch (Exception e) {
            throw new CryptographyException(e);
        }
    }

    private Cipher buildCipher(int cipherMode, Encryption encryption, SecretKey key) throws Exception {
        if (encryption == null) {
            throw new IllegalStateException("BCCryptographer needs to be initialized with a valid encryption");
        }
        String instanceCall = encryption.type.getName();
        if(!encryption.type.isStreamType()) {
            instanceCall += "/" + encryption.mode.toString();
            instanceCall += "/" + encryption.options;
        }
        Cipher c = Cipher.getInstance(instanceCall, "BC");

        if(encryption.mode.isVectorMode()) {
            if(encryption.getInitializationVector() != null) {
                c.init(cipherMode, key, new IvParameterSpec(encryption.getInitializationVector()));
            } else {
                c.init(cipherMode, key);
                encryption.setInitializationVector(c.getIV());
            }
        } else {
            c.init(cipherMode, key);
        }
        return c;
    }



}
