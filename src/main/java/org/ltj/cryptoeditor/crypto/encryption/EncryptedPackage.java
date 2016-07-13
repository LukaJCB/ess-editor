package org.ltj.cryptoeditor.crypto.encryption;

import com.google.gson.Gson;

/**
 * Represents the documents to be parsed to JSON that incorporates all things necessary to decrypt the message inside.
 */
public class EncryptedPackage {

    public final Encryption encryption;
    public final String payload;
    public final boolean needsPassword;
    public final HashPayload checkSum;

    public EncryptedPackage(Encryption encryption, String payload,boolean needsPassword, HashPayload checkSum){
        this.encryption = encryption;
        this.payload = payload;
        this.needsPassword = needsPassword;
        this.checkSum = checkSum;
    }

    public String toJson(){
        return new Gson().toJson(this);
    }

    public static EncryptedPackage fromJson(String json){
        return new Gson().fromJson(json, EncryptedPackage.class);
    }
}
