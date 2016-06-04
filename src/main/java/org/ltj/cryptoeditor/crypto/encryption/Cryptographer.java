package org.ltj.cryptoeditor.crypto.encryption;

import org.ltj.cryptoeditor.crypto.exception.CryptographyException;

import javax.crypto.SecretKey;
import java.io.IOException;


public interface Cryptographer {

    String encrypt(String input, Encryption encryption, SecretKey key) throws CryptographyException, IOException;
    String decrypt(String input, Encryption encryption, SecretKey key) throws CryptographyException, IOException;
}
