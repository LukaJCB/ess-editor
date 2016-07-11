package org.ltj.cryptoeditor.crypto.encryption;

/**
 * Created by Luka on 11.07.2016.
 */
public class HashDecryptionResult {
    public final boolean temperedWith;
    public final String plainText;

    public HashDecryptionResult(boolean temperedWith, String plainText){
        this.temperedWith = temperedWith;
        this.plainText = plainText;
    }
}
