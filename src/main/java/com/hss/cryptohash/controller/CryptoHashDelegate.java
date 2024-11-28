package com.hss.cryptohash.controller;

import com.hss.cryptohash.commons.Algorithm;
import com.hss.cryptohash.commons.dto.EncryptionRequestDTO;
import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.MatchedResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import jakarta.inject.Singleton;

@Singleton
public class CryptoHashDelegate {

    private Algorithm strategy;

    public void setStrategy(String strategy) {
        this.strategy = Algorithm.valueOf(strategy);
    }

    public MatchedResponseDTO match(PasswordMatchingRequestDTO dto) {
        return this.strategy.getStrategy().matches(dto);
    }

    public EncryptionResponseDTO encrypt(EncryptionRequestDTO dto) {
        return this.strategy.getStrategy().encrypt(dto.password());
    }
}