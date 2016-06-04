package org.ltj.cryptoeditor.crypto.exception;


public class CryptographyException extends RuntimeException {
    public CryptographyException(Throwable e) {
        super(e);
    }

    public CryptographyException(String m) {
        super(m);
    }
}
