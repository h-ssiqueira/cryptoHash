package com.hss.cryptohash.commons.dto;


import java.io.Serializable;

public record PasswordMatchingDTO(String rawPassword, String encryptedPassword) implements Serializable {
}
