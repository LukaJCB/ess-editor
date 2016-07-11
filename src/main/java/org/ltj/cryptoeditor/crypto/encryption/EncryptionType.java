package org.ltj.cryptoeditor.crypto.encryption;


public enum EncryptionType {
    AES("AES", false, EncryptionMode.values()),
    DES("DES", false, EncryptionMode.values()),
    ARC4("ARC4", true, new EncryptionMode[0]);

    private final String name;
    private final boolean isStreamType;
    private final EncryptionMode[] supportedModes;

    EncryptionType(String name, boolean isStreamType, EncryptionMode[] supportedModes) {
        this.name = name;
        this.isStreamType = isStreamType;
        this.supportedModes = supportedModes;
    }

    public String getName() {
        return name;
    }

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

    public boolean isStreamType() {
        return isStreamType;
    }

    public EncryptionMode[] getSupportedModes() {
        return supportedModes;
    }

}
