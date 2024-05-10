package com.hss.cryptohash.commons.dto;

import jakarta.validation.constraints.NotBlank;

import java.io.Serializable;

public record EncryptionRequestDTO(@NotBlank String password) implements Serializable {
}
