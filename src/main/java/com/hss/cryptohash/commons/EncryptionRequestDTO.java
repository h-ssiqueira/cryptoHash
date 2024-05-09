package com.hss.cryptohash.commons;

import jakarta.validation.constraints.NotBlank;

public record EncryptionRequestDTO(@NotBlank String password) {
}
