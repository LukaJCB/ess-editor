package org.ltj.cryptoeditor.crypto.encryption;

/**
 * The Result returned after decrypting a cipher text with a hash.
 */
public class HashDecryptionResult {
    /**
     * True if the cipher text has been tampered with
     */
    public final boolean temperedWith;
    /**
     * The resulting plain text.
     */
    public final String plainText;

    public HashDecryptionResult(boolean temperedWith, String plainText){
        this.temperedWith = temperedWith;
        this.plainText = plainText;
    }
}
