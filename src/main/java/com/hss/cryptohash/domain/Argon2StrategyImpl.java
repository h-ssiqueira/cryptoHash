package com.hss.cryptohash.domain;

import com.hss.cryptohash.commons.EncryptionResponseDTO;
import com.hss.cryptohash.commons.MatchedResponseDTO;
import com.hss.cryptohash.commons.PasswordMatchingDTO;
import com.hss.cryptohash.spec.CryptoHashStrategy;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

import java.time.Duration;
import java.time.Instant;

import static com.hss.cryptohash.commons.logging.LoggingConstants.LOG001;

@Slf4j
public class Argon2StrategyImpl implements CryptoHashStrategy {

    @ConfigProperty(name = "hash.argon2.saltLength")
    private int saltLength;
    @ConfigProperty(name = "hash.argon2.hashLength")
    private int hashLength;
    @ConfigProperty(name = "hash.argon2.parallelism")
    private int parallelism;
    @ConfigProperty(name = "hash.argon2.memory")
    private int memory;
    @ConfigProperty(name = "hash.argon2.iterations")
    private int iterations;

    private final Argon2PasswordEncoder argon2 = new Argon2PasswordEncoder(saltLength, hashLength, parallelism, memory, iterations);

    @Override
    public EncryptionResponseDTO encrypt(String password) {
        var start = Instant.now();
        var encrypted = argon2.encode(password);
        var end = Instant.now();
        log.info(LOG001, "encrypt", "Argon2", Duration.between(start, end).toMillis());
        return new EncryptionResponseDTO(encrypted);
    }

    @Override
    public MatchedResponseDTO matches(PasswordMatchingDTO passwordMatchingDTO) {
        var start = Instant.now();
        var match = argon2.matches(passwordMatchingDTO.rawPassword(), passwordMatchingDTO.encryptedPassword());
        var end = Instant.now();
        log.info(LOG001, "match", "BCrypt", Duration.between(start, end).toMillis());
        return new MatchedResponseDTO(match);
    }
}
