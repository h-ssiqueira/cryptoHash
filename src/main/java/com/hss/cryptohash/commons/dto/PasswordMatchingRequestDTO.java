package com.hss.cryptohash.commons.dto;


import java.io.Serializable;

public record PasswordMatchingRequestDTO(String rawPassword, String encryptedPassword) implements Serializable {
}