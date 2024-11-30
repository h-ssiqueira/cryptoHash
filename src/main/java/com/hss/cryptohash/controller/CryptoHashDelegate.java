package com.hss.cryptohash.controller;

import com.hss.cryptohash.commons.config.ConfigApplicationProperties;
import com.hss.cryptohash.commons.dto.EncryptionRequestDTO;
import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.strategy.Algorithm;
import com.hss.cryptohash.commons.strategy.AlgorithmStrategyEnum;
import com.hss.cryptohash.domain.Blake3StrategyImpl;
import com.hss.cryptohash.domain.md.MD2StrategyImpl;
import com.hss.cryptohash.domain.md.MD5StrategyImpl;
import com.hss.cryptohash.domain.secure.Argon2StrategyImpl;
import com.hss.cryptohash.domain.secure.BcryptStrategyImpl;
import com.hss.cryptohash.domain.secure.PBKDF2StrategyImpl;
import com.hss.cryptohash.domain.secure.ScryptStrategyImpl;
import com.hss.cryptohash.domain.sha.SHA1StrategyImpl;
import com.hss.cryptohash.domain.sha.SHA256StrategyImpl;
import com.hss.cryptohash.domain.sha.SHA384StrategyImpl;
import com.hss.cryptohash.domain.sha.SHA3_224StrategyImpl;
import com.hss.cryptohash.domain.sha.SHA3_256StrategyImpl;
import com.hss.cryptohash.domain.sha.SHA3_384StrategyImpl;
import com.hss.cryptohash.domain.sha.SHA3_512StrategyImpl;
import com.hss.cryptohash.domain.sha.SHA512StrategyImpl;
import com.hss.cryptohash.domain.sha.SHA512_224StrategyImpl;
import com.hss.cryptohash.domain.sha.SHA512_256StrategyImpl;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

@Singleton
public class CryptoHashDelegate {

    private final ConfigApplicationProperties properties;

    private final Algorithm strategy;

    @Inject
    public CryptoHashDelegate(ConfigApplicationProperties properties) {
        this.properties = properties;
        this.strategy = new Algorithm();
    }

    public void setStrategy(String strategy) {
        this.strategy.setStrategy(
            switch (AlgorithmStrategyEnum.valueOf(strategy)) {
                case ARGON2 -> new Argon2StrategyImpl(properties.argon2());
                case BCRYPT -> new BcryptStrategyImpl(properties.bcrypt());
                case SCRYPT -> new ScryptStrategyImpl(properties.scrypt());
                case PBKDF2 -> new PBKDF2StrategyImpl(properties.pbkdf2());
                case MD2 -> new MD2StrategyImpl();
                case MD5 -> new MD5StrategyImpl();
                case SHA1 -> new SHA1StrategyImpl();
                case SHA256 -> new SHA256StrategyImpl();
                case SHA3_224 -> new SHA3_224StrategyImpl();
                case SHA3_256 -> new SHA3_256StrategyImpl();
                case SHA3_512 -> new SHA3_512StrategyImpl();
                case SHA3_384 -> new SHA3_384StrategyImpl();
                case SHA384 -> new SHA384StrategyImpl();
                case SHA512_224 -> new SHA512_224StrategyImpl();
                case SHA512_256 -> new SHA512_256StrategyImpl();
                case SHA512 -> new SHA512StrategyImpl();
                case BLAKE3 -> new Blake3StrategyImpl(properties.blake3());
        });
    }

    public void match(PasswordMatchingRequestDTO dto) {
        this.strategy.getStrategy().matches(dto);
    }

    public EncryptionResponseDTO encrypt(EncryptionRequestDTO dto) {
        return this.strategy.getStrategy().encrypt(dto.password());
    }
}