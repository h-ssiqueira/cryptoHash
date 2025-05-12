package com.hss.cryptohash.commons.dto;

import io.quarkus.runtime.annotations.RegisterForReflection;

import java.io.Serializable;

@RegisterForReflection
public record EncryptionResponseDTO(String passwordEncrypted) implements Serializable {
}