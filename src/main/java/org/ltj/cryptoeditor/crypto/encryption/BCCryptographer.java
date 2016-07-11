package org.ltj.cryptoeditor.crypto.encryption;

import org.apache.commons.io.IOUtils;
import org.ltj.cryptoeditor.crypto.exception.CryptographyException;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.*;
import java.security.spec.KeySpec;


public class BCCryptographer implements Cryptographer {


    private final static BCCryptographer instance = new BCCryptographer();
    private final static Charset charset = Charset.forName("ISO-8859-1");
    private final static String hashAlgorithm = "SHA-1";


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

        byte[] bytes = input.getBytes(charset);
        InputStream stream = getEncryptionStream(new ByteArrayInputStream(bytes), encryption, generateKey(password.toCharArray(),encryption));
        return streamToString(stream);
    }

    public String decrypt(String input, Encryption encryption, SecretKey key) throws IOException{
        byte[] bytes = input.getBytes(charset);
        InputStream stream = getDecryptionStream(new ByteArrayInputStream(bytes), encryption, key);

        return streamToString(stream);
    }

    public String decrypt(String input, String password, Encryption encryption) throws Exception{
        byte[] bytes = input.getBytes(charset);
        InputStream stream = getDecryptionStream(new ByteArrayInputStream(bytes), encryption, generateKey(password.toCharArray(),encryption));

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


    public HashPayload encryptWithHash(String input, Encryption encryption, SecretKey key) throws Exception{
        Cipher cipher = generateCipher(Cipher.ENCRYPT_MODE, encryption, key);
        MessageDigest digest = MessageDigest.getInstance(hashAlgorithm, "BC");

        byte[] cipherText = new byte[cipher.getOutputSize(input.length() + digest.getDigestLength())];
        int ctLength = cipher.update(input.getBytes(charset),0, input.length(),cipherText,0);

        digest.update(input.getBytes(charset));

        ctLength += cipher.doFinal(digest.digest(),0, digest.getDigestLength(), cipherText, ctLength);

        return new HashPayload(cipherText,ctLength);
    }

    public HashDecryptionResult decryptWithHash(HashPayload payload, Encryption encryption, SecretKey key) throws Exception {
        Cipher cipher = generateCipher(Cipher.DECRYPT_MODE, encryption, key);
        MessageDigest digest = MessageDigest.getInstance(hashAlgorithm, "BC");

        byte[] decryptedText = cipher.doFinal(payload.cipherText, 0, payload.ctLength);
        int messageLength = decryptedText.length - digest.getDigestLength();

        digest.update(decryptedText,0,messageLength);

        byte[] messageHash = new byte[digest.getDigestLength()];
        System.arraycopy(decryptedText, messageLength, messageHash, 0, messageHash.length);

        boolean verified = MessageDigest.isEqual(digest.digest(), messageHash);

        byte[] plainText = new byte[messageLength];
        System.arraycopy(decryptedText,0, plainText, 0, messageLength);

        return new HashDecryptionResult(!verified, new String(plainText,charset));
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

    private SecretKey generateKey(char[] password, Encryption encryption) throws Exception {
        byte[] salt = new byte[]{
                0x7d, 0x60, 0x43, 0x5f,
                0x02, (byte) 0xe9, (byte) 0xe0, (byte) 0xae};

        SecretKeyFactory factory = SecretKeyFactory.getInstance(encryption.type.getPbeType(), "BC");
        KeySpec spec = new PBEKeySpec(password, salt, 65536, encryption.type.getKeyLength());
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), encryption.type.getName());

    }




}
