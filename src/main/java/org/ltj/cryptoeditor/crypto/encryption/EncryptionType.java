package org.ltj.cryptoeditor.crypto.encryption;


/**
 * The type of the encryption to use
 */
public enum EncryptionType {
    AES(false, EncryptionMode.values()),
    DES(false, EncryptionMode.values()),
    ARC4(true, new EncryptionMode[0]);

    /**
     * true if the given type is a stream type (e.g. RC4)
     */
    public final boolean isStreamType;
    /**
     * The supported modes for this encryptionType
     */
    public final EncryptionMode[] supportedModes;

    EncryptionType(boolean isStreamType, EncryptionMode[] supportedModes) {
        this.isStreamType = isStreamType;
        this.supportedModes = supportedModes;
    }


    /**
     * Returns the Recommended length of the key for this type.
     * @return the  recommended key length
     */
    public int getKeyLength(){
        switch (this){
            case AES:
                return 128;
            case DES:
                return 64;
            case ARC4:
                return 256;
        }
        return 128;
    }

    /**
     * The Algorithm to use with this encryption type.
     * @return a String representing the algorithm to use
     */
    public String getPbeType(){
        switch (this){
            case AES:
                return "PBEWITHSHA256AND128BITAES-CBC-BC";
            case DES:
                return "PBEWithMD5AndDES";
            case ARC4:
                return "PBEWithSHAAnd40BitRC4";
        }
        return "PBEWITHSHA256AND128BITAES-CBC-BC";
    }


}
