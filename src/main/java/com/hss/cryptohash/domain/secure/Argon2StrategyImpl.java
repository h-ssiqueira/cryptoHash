package com.hss.cryptohash.domain.secure;

import com.hss.cryptohash.commons.config.ConfigApplicationProperties;
import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.exception.CryptoHashException;
import com.hss.cryptohash.spec.CryptoHashStrategy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

import java.time.Duration;
import java.time.Instant;

import static com.hss.cryptohash.commons.logging.LoggingConstants.LOG001;

@Slf4j
public class Argon2StrategyImpl implements CryptoHashStrategy {

    private final Argon2PasswordEncoder argon2;

    public Argon2StrategyImpl(ConfigApplicationProperties.Argon2Properties properties) {
        argon2 = new Argon2PasswordEncoder(properties.saltLength(), properties.hashLength(), properties.parallelism(), properties.memory(), properties.iterations());
    }

    @Override
    public EncryptionResponseDTO encrypt(String password) {
        var start = Instant.now();
        var encrypted = argon2.encode(password);
        var end = Instant.now();
        log.info(LOG001, "encrypt", "Argon2", Duration.between(start, end).toMillis());
        return new EncryptionResponseDTO(encrypted);
    }

    @Override
    public void matches(PasswordMatchingRequestDTO passwordMatchingRequestDTO) {
        var start = Instant.now();
        var match = argon2.matches(passwordMatchingRequestDTO.rawPassword(), passwordMatchingRequestDTO.encryptedPassword());
        var end = Instant.now();
        log.info(LOG001, "match", "BCrypt", Duration.between(start, end).toMillis());
        if (!match) {
            throw new CryptoHashException("Invalid password!");
        }
    }
}