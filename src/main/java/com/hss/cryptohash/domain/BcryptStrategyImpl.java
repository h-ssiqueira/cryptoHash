package com.hss.cryptohash.domain;

import com.hss.cryptohash.commons.EncryptionResponseDTO;
import com.hss.cryptohash.commons.MatchedResponseDTO;
import com.hss.cryptohash.commons.PasswordMatchingDTO;
import com.hss.cryptohash.spec.CryptoHashStrategy;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.time.Duration;
import java.time.Instant;

import static com.hss.cryptohash.commons.logging.LoggingConstants.LOG001;

@Slf4j
public class BcryptStrategyImpl implements CryptoHashStrategy {

    @ConfigProperty(name = "hash.bcrypt.strength")
    private int strength;

    private final BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder(strength);

    @Override
    public EncryptionResponseDTO encrypt(String password) {
        var start = Instant.now();
        var encrypted = bcrypt.encode(password);
        var end = Instant.now();
        log.info(LOG001, "encrypt", "BCrypt", Duration.between(start, end).toMillis());
        return new EncryptionResponseDTO(encrypted);
    }

    @Override
    public MatchedResponseDTO matches(PasswordMatchingDTO passwordMatchingDTO) {
        var start = Instant.now();
        var match = bcrypt.matches(passwordMatchingDTO.rawPassword(), passwordMatchingDTO.encryptedPassword());
        var end = Instant.now();
        log.info(LOG001, "match", "BCrypt", Duration.between(start, end).toMillis());
        return new MatchedResponseDTO(match);
    }
}
