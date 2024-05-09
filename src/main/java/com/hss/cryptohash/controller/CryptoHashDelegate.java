package com.hss.cryptohash.controller;

import com.hss.cryptohash.commons.Algorithm;
import com.hss.cryptohash.commons.EncryptionRequestDTO;
import com.hss.cryptohash.commons.EncryptionResponseDTO;
import com.hss.cryptohash.commons.MatchedResponseDTO;
import com.hss.cryptohash.commons.PasswordMatchingDTO;
import jakarta.inject.Singleton;

@Singleton
public class CryptoHashDelegate {

    private Algorithm strategy;

    public void setStrategy(String strategy) {
        this.strategy = Algorithm.valueOf(strategy);
    }

    public MatchedResponseDTO match(PasswordMatchingDTO dto) {
        return this.strategy.getStrategy().matches(dto);
    }

    public EncryptionResponseDTO encrypt(EncryptionRequestDTO dto) {
        return this.strategy.getStrategy().encrypt(dto.password());
    }
}
