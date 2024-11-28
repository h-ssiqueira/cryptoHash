package com.hss.cryptohash.commons.exception;

import lombok.Getter;

@Getter
public class CryptoHashException extends RuntimeException {

    private final String clazz;

    public CryptoHashException(String message) {
        super(message);
        this.clazz = "CryptoHashException";
    }

    public CryptoHashException(Exception ex) {
        super(ex);
        this.clazz = ex.getClass().toString();
    }
}