package org.ltj.cryptoeditor.crypto.encryption;

/**
 * Created by Luka on 11.07.2016.
 */
public class HashPayload {

    public final byte[] cipherText;
    public final int ctLength;

    public HashPayload(byte[] cipherText, int ctLength){
        this.cipherText = cipherText;
        this.ctLength = ctLength;
    }
}
