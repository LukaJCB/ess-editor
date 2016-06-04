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

    public boolean isStreamType() {
        return isStreamType;
    }

    public EncryptionMode[] getSupportedModes() {
        return supportedModes;
    }

}
