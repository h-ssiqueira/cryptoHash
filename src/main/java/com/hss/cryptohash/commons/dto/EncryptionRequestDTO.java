package com.hss.cryptohash.commons.dto;

import jakarta.validation.constraints.NotBlank;

public record EncryptionRequestDTO(@NotBlank String password) {
}
