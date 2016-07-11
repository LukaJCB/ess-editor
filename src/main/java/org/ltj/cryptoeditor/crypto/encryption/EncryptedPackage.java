package org.ltj.cryptoeditor.crypto.encryption;

import com.google.gson.Gson;

/**
 * Created by Luka on 11.07.2016.
 */
public class EncryptedPackage {

    public final Encryption encryption;
    public final String payload;
    public final String checkSum;

    public EncryptedPackage(Encryption encryption, String payload, String checkSum){
        this.encryption = encryption;
        this.payload = payload;
        this.checkSum = checkSum;
    }

    public String toJson(){
        return new Gson().toJson(this);
    }

    public static EncryptedPackage fromJson(String json){
        return new Gson().fromJson(json, EncryptedPackage.class);
    }
}
