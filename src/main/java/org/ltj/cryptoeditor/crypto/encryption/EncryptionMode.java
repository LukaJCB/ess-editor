package org.ltj.cryptoeditor.crypto.encryption;


/**
 * The Class holding the information about which cipher mode to use.
 */
public enum EncryptionMode {

    ECB(false, false, EncryptionOptions.values()),
    CBC(true, false, EncryptionOptions.values()),
    CTR(true, true, EncryptionOptions.NoPadding),
    OFB(true, true, EncryptionOptions.NoPadding),
    CFB(true, true, EncryptionOptions.NoPadding),
    GCM(true, true, EncryptionOptions.NoPadding);

    /**
     * True if the mode needs an initialization Vector
     */
    public final boolean isVectorMode;
    /**
     * True if the mode is a stream cipher mode
     */
    public final boolean isStreamMode;
    /**
     * The Options this particular mode supports.
     */
    public final EncryptionOptions[] supportedPaddings;

    EncryptionMode(boolean isVectorMode, boolean isStreamMode, EncryptionOptions... supportedPaddings) {
        this.isVectorMode = isVectorMode;
        this.supportedPaddings = supportedPaddings;
        this.isStreamMode = isStreamMode;
    }

}