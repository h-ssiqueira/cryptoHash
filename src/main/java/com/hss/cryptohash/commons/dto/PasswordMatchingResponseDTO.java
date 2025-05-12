package com.hss.cryptohash.commons.dto;

import io.quarkus.runtime.annotations.RegisterForReflection;

import java.io.Serializable;

@RegisterForReflection
public record PasswordMatchingResponseDTO(Boolean match) implements Serializable {
    
    public PasswordMatchingResponseDTO(int match){
        this(match == 0);
    }
}