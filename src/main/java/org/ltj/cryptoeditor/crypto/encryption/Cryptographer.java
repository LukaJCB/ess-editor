package org.ltj.cryptoeditor.crypto.encryption;

import org.ltj.cryptoeditor.crypto.exception.CryptographyException;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;


public interface Cryptographer {

    /**
     * Symmetrically encrypts the given String with the given encryption parameters and the given key.
     * @param input the String to be encrypted
     * @param encryption the encryption parameters
     * @param key the key to use in the encryption
     * @return the encrypted ciphertext.
     * @throws IOException
     */
    String encrypt(String input, Encryption encryption, SecretKey key) throws CryptographyException, IOException;

    /**
     * Symmetrically encrypts the given String with PBE and the given encryption parameters.
     * @param input the String to be encrypted
     * @param password the String to use as a password for PBE
     * @param encryption the encryption parameters
     * @return the encrypted ciphertext.
     * @throws IOException
     */
    String encrypt(String input, String password, Encryption encryption) throws Exception;

    /**
     * Symmetrically decrypts the given String with the given encryption parameters and the given key.
     * @param input the String to be decrypted
     * @param encryption the encryption parameters
     * @param key the key to use in the encryption
     * @return the decrypted plaintext.
     * @throws IOException
     */
    String decrypt(String input, Encryption encryption, SecretKey key) throws CryptographyException, IOException;

    /**
     * Symmetrically decrypts the given String with the given encryption parameters and PBE.
     * @param input the String to be encrypted
     * @param password the password to be used for PBE
     * @param encryption the encryption parameters
     * @return the decrypted plaintext.
     * @throws IOException
     */
    String decrypt(String input, String password, Encryption encryption) throws Exception;

    /**
     * Asymmetrically encrypts the given String using the RSA algorithm.
     * @param input the String to be encrypted
     * @param publicKey the public key used in the RSA algorithm
     * @return the encrypted ciphertext
     * @throws Exception
     */
    String encryptRsa(String input, RSAPublicKey publicKey) throws Exception;

    /**
     * Asymmetrically decrypts the given String using the RSA algorithm.
     * @param input the String to be encrypted
     * @param privateKey the private key used in the RSA algorithm
     * @return the encrypted ciphertext
     * @throws Exception
     */
    String decryptRsa(String input, RSAPrivateKey privateKey) throws Exception;
    /**
     * Generates an RSAPublicKey based on the given modulo.
     * @param modulo the modulo to be used
     * @return the generated key
     * @throws Exception
     */
    RSAPublicKey generatePublicKey(String modulo) throws Exception;
    /**
     * Generates an RSAPrivateKey.
     * @param modulo the modulo to be used
     * @param privateExponent the exponent to be used
     * @return the generated key
     * @throws Exception
     */
    RSAPrivateKey generatePrivateKey(String modulo, String privateExponent) throws Exception;
    /**
     * Symmetrically encrypts the given String with the given encryption parameters, the given key and appends an SHA-1 hash.
     * @param input the String to be encrypted
     * @param encryption the encryption parameters
     * @param key the key to use in the encryption
     * @return the encrypted ciphertext appended by the hash
     * @throws IOException
     */
    HashPayload encryptWithHash(String input, Encryption encryption, SecretKey key) throws Exception;
    /**
     * Symmetrically decrypts the given String with the given encryption parameters, the given key and checks the validity of the checksum.
     * @param payload the String to be decrypted
     * @param encryption the encryption parameters
     * @param key the key to use in the decryption
     * @return the decrypted plaintext and the validity of the checksum
     * @throws IOException
     */
    HashDecryptionResult decryptWithHash(HashPayload payload, Encryption encryption, SecretKey key) throws Exception;
    /**
     * Symmetrically encrypts the given String with a password and the given encryption parameters and appends an SHA-1 hash.
     * @param input the String to be encrypted
     * @param password the password to be used for PBE
     * @param encryption the encryption parameters
     * @return the encrypted ciphertext appended by the hash
     * @throws IOException
     */
    HashPayload encryptWithHash(String input, String password, Encryption encryption) throws Exception;
    /**
     * Symmetrically decrypts the given String with a password and the given encryption parametersand checks the validity of the checksum.
     * @param payload the String to be decrypted
     * @param password the password to be used for PBE
     * @param encryption the encryption parameters
     * @return the decrypted plaintext and the validity of the checksum
     * @throws IOException
     */
    HashDecryptionResult decryptWithHash(HashPayload payload, String password, Encryption encryption) throws Exception;
}
