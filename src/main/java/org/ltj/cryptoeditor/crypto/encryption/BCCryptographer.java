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
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

/**
 * Provides an implementation to the Cryptographer interface based on the Bouncy Castle provider as a Singleton.
 */
public class BCCryptographer implements Cryptographer {


    private final static BCCryptographer instance = new BCCryptographer();
    private final static Charset charset = Charset.forName("ISO-8859-1");
    private final static String hashAlgorithm = "SHA-1";


    private BCCryptographer(){}

    /**
     * Returns the instance of the Cryptographer Object.
     * @return the instance of the Cryptographer Object.
     */
    public static BCCryptographer getInstance(){
        return instance;
    }

    /**
     * Symmetrically encrypts the given String with the given encryption parameters and the given key.
     * @param input the String to be encrypted
     * @param encryption the encryption parameters
     * @param key the key to use in the encryption
     * @return the encrypted ciphertext.
     * @throws IOException
     */
    public String encrypt(String input, Encryption encryption, SecretKey key) throws IOException{
        byte[] bytes = input.getBytes(charset);
        InputStream stream = getEncryptionStream(new ByteArrayInputStream(bytes), encryption, key);
        return streamToString(stream);
    }

    /**
     * Symmetrically encrypts the given String with PBE and the given encryption parameters.
     * @param input the String to be encrypted
     * @param password the String to use as a password for PBE
     * @param encryption the encryption parameters
     * @return the encrypted ciphertext.
     * @throws IOException
     */
    public String encrypt(String input, String password, Encryption encryption) throws Exception{

        byte[] bytes = input.getBytes(charset);
        InputStream stream = getEncryptionStream(new ByteArrayInputStream(bytes), encryption, generateKey(password.toCharArray(),encryption));
        return streamToString(stream);
    }

    /**
     * Asymmetrically encrypts the given String using the RSA algorithm.
     * @param input the String to be encrypted
     * @param publicKey the public key used in the RSA algorithm
     * @return the encrypted ciphertext
     * @throws Exception
     */
    public String encryptRsa(String input, RSAPublicKey publicKey) throws Exception {
        byte[] bytes = input.getBytes(charset);
        Cipher cipher = Cipher.getInstance("RSA/None/NoPadding","BC");

        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherText = cipher.doFinal(bytes);

        return new String(cipherText,charset);
    }

    /**
     * Asymmetrically decrypts the given String using the RSA algorithm.
     * @param input the String to be encrypted
     * @param privateKey the private key used in the RSA algorithm
     * @return the encrypted ciphertext
     * @throws Exception
     */
    public String decryptRsa(String input, RSAPrivateKey privateKey) throws Exception {
        byte[] bytes = input.getBytes(charset);
        Cipher cipher = Cipher.getInstance("RSA/None/NoPadding","BC");


        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] plainText = cipher.doFinal(bytes);

        return new String(plainText,charset);
    }

    /**
     * Generates an RSAPublicKey based on the given modulo.
     * @param modulo the modulo to be used
     * @return the generated key
     * @throws Exception
     */
    public RSAPublicKey generatePublicKey(String modulo) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
            RSAPublicKeySpec spec = new RSAPublicKeySpec(new BigInteger(modulo, 16), new BigInteger("11", 16));

            return (RSAPublicKey) keyFactory.generatePublic(spec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Generates an RSAPrivateKey.
     * @param modulo the modulo to be used
     * @param privateExponent the exponent to be used
     * @return the generated key
     * @throws Exception
     */
    public RSAPrivateKey generatePrivateKey(String modulo, String privateExponent){
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
            RSAPrivateKeySpec spec = new RSAPrivateKeySpec(new BigInteger(modulo, 16), new BigInteger(privateExponent, 16));
            return (RSAPrivateKey)keyFactory.generatePrivate(spec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Symmetrically decrypts the given String with the given encryption parameters and the given key.
     * @param input the String to be decrypted
     * @param encryption the encryption parameters
     * @param key the key to use in the encryption
     * @return the decrypted plaintext.
     * @throws IOException
     */
    public String decrypt(String input, Encryption encryption, SecretKey key) throws IOException{
        byte[] bytes = input.getBytes(charset);
        InputStream stream = getDecryptionStream(new ByteArrayInputStream(bytes), encryption, key);

        return streamToString(stream);
    }

    /**
     * Symmetrically decrypts the given String with the given encryption parameters and PBE.
     * @param input the String to be encrypted
     * @param password the password to be used for PBE
     * @param encryption the encryption parameters
     * @return the decrypted plaintext.
     * @throws IOException
     */
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


    /**
     * Symmetrically encrypts the given String with the given encryption parameters, the given key and appends an SHA-1 hash.
     * @param input the String to be encrypted
     * @param encryption the encryption parameters
     * @param key the key to use in the encryption
     * @return the encrypted ciphertext appended by the hash
     * @throws IOException
     */
    public HashPayload encryptWithHash(String input, Encryption encryption, SecretKey key) throws Exception{
        Cipher cipher = generateCipher(Cipher.ENCRYPT_MODE, encryption, key);
        MessageDigest digest = MessageDigest.getInstance(hashAlgorithm, "BC");

        byte[] cipherText = new byte[cipher.getOutputSize(input.length() + digest.getDigestLength())];
        int ctLength = cipher.update(input.getBytes(charset),0, input.length(),cipherText,0);

        digest.update(input.getBytes(charset));

        ctLength += cipher.doFinal(digest.digest(),0, digest.getDigestLength(), cipherText, ctLength);

        return new HashPayload(new String(cipherText,charset),ctLength);
    }

    /**
     * Symmetrically decrypts the given String with the given encryption parameters, the given key and checks the validity of the checksum.
     * @param payload the String to be decrypted
     * @param encryption the encryption parameters
     * @param key the key to use in the decryption
     * @return the decrypted plaintext and the validity of the checksum
     * @throws IOException
     */
    public HashDecryptionResult decryptWithHash(HashPayload payload, Encryption encryption, SecretKey key) throws Exception {
        Cipher cipher = generateCipher(Cipher.DECRYPT_MODE, encryption, key);
        MessageDigest digest = MessageDigest.getInstance(hashAlgorithm, "BC");

        byte[] decryptedText = cipher.doFinal(payload.cipherText.getBytes(charset), 0, payload.ctLength);
        int messageLength = decryptedText.length - digest.getDigestLength();

        digest.update(decryptedText,0,messageLength);

        byte[] messageHash = new byte[digest.getDigestLength()];
        System.arraycopy(decryptedText, messageLength, messageHash, 0, messageHash.length);

        boolean verified = MessageDigest.isEqual(digest.digest(), messageHash);

        byte[] plainText = new byte[messageLength];
        System.arraycopy(decryptedText,0, plainText, 0, messageLength);

        return new HashDecryptionResult(!verified, new String(plainText,charset));
    }

    /**
     * Symmetrically encrypts the given String with a password and the given encryption parameters and appends an SHA-1 hash.
     * @param input the String to be encrypted
     * @param password the password to be used for PBE
     * @param encryption the encryption parameters
     * @return the encrypted ciphertext appended by the hash
     * @throws IOException
     */
    public HashPayload encryptWithHash(String input, String password, Encryption encryption) throws Exception{
        Cipher cipher = generateCipher(Cipher.ENCRYPT_MODE, encryption, generateKey(password.toCharArray(),encryption));
        MessageDigest digest = MessageDigest.getInstance(hashAlgorithm, "BC");

        byte[] cipherText = new byte[cipher.getOutputSize(input.length() + digest.getDigestLength())];
        int ctLength = cipher.update(input.getBytes(charset),0, input.length(),cipherText,0);

        digest.update(input.getBytes(charset));

        ctLength += cipher.doFinal(digest.digest(),0, digest.getDigestLength(), cipherText, ctLength);

        return new HashPayload(new String(cipherText,charset),ctLength);
    }

    /**
     * Symmetrically decrypts the given String with a password and the given encryption parametersand checks the validity of the checksum.
     * @param payload the String to be decrypted
     * @param password the password to be used for PBE
     * @param encryption the encryption parameters
     * @return the decrypted plaintext and the validity of the checksum
     * @throws IOException
     */
    public HashDecryptionResult decryptWithHash(HashPayload payload,  String password,Encryption encryption) throws Exception {
        Cipher cipher = generateCipher(Cipher.DECRYPT_MODE, encryption, generateKey(password.toCharArray(),encryption));
        MessageDigest digest = MessageDigest.getInstance(hashAlgorithm, "BC");

        byte[] decryptedText = cipher.doFinal(payload.cipherText.getBytes(charset), 0, payload.ctLength);
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
        String transformation = encryption.type.toString();
        if(!encryption.type.isStreamType) {
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
        return new SecretKeySpec(tmp.getEncoded(), encryption.type.toString());

    }




}
