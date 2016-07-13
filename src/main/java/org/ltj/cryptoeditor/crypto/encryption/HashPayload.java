package org.ltj.cryptoeditor.crypto.encryption;

/**
 * The Result of encrypting with a hash.
 */
public class HashPayload {

    public final String cipherText;
    public final int ctLength;

    public HashPayload(String cipherText, int ctLength){
        this.cipherText = cipherText;
        this.ctLength = ctLength;
    }
}
