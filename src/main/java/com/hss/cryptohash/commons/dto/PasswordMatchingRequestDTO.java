package com.hss.cryptohash.commons.dto;


import java.io.Serializable;

public record PasswordMatchingRequestDTO(String rawPassword, String encryptedPassword) implements Serializable {

    public byte[] encryptedPasswordBytes() {
        return encryptedPassword.getBytes();
    }

    public byte[] rawPasswordBytes() {
        return rawPassword.getBytes();
    }
}