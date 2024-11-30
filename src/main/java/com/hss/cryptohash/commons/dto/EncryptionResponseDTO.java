package com.hss.cryptohash.commons.dto;

import java.io.Serializable;

public record EncryptionResponseDTO(String passwordEncrypted) implements Serializable {
}
