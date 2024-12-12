package com.hss.cryptohash.commons.dto;

import java.io.Serializable;

public record PasswordMatchingResponseDTO(Boolean match) implements Serializable {
    
    public PasswordMatchingResponseDTO(int match){
        this(match == 0);
    }
}
