package org.ltj.cryptoeditor.crypto.encryption;

/**
 * The Class holding the information on how to encrypt and decrypt a given message symmetrically.
 */
public class Encryption {

    /**
     *
     */
    public final EncryptionType type;

    public final EncryptionMode mode;

    public final EncryptionOptions options;

    private byte[] initializationVector;

    public Encryption(EncryptionType type, EncryptionMode mode, EncryptionOptions options) {
        this.type = type;
        this.mode = mode;
        this.options = options;
    }

    public Encryption(EncryptionType type, EncryptionMode mode) {
        this.type = type;
        this.mode = mode;
        this.options = EncryptionOptions.NoPadding;
    }

    public Encryption(EncryptionType type) {
        this.type = type;
        this.mode = EncryptionMode.ECB;
        this.options = EncryptionOptions.NoPadding;
    }


    public byte[] getInitializationVector() {
        return initializationVector;
    }

    public void setInitializationVector(byte[] initializationVector) {
        this.initializationVector = initializationVector;
    }
}

