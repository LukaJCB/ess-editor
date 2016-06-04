package org.ltj.cryptoeditor.crypto.encryption;



public enum EncryptionMode {

    ECB(false, false, EncryptionOptions.values()),
    CBC(true, false, EncryptionOptions.values()),
    CTR(true, true, EncryptionOptions.NoPadding),
    OFB(true, true, EncryptionOptions.NoPadding),
    CFB(true, true, EncryptionOptions.NoPadding),
    GCM(true, true, EncryptionOptions.NoPadding);

    private final boolean isVectorMode;
    private final boolean isStreamMode;
    private final EncryptionOptions[] supportedPaddings;

    EncryptionMode(boolean isVectorMode, boolean isStreamMode, EncryptionOptions... supportedPaddings) {
        this.isVectorMode = isVectorMode;
        this.supportedPaddings = supportedPaddings;
        this.isStreamMode = isStreamMode;
    }


    public boolean isVectorMode() {
        return isVectorMode;
    }

    public boolean isStreamMode() {
        return isStreamMode;
    }


    public EncryptionOptions[] getSupportedPaddings() {
        return supportedPaddings;
    }
}