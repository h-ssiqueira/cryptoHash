package com.hss.cryptohash.domain.secure;

import com.hss.cryptohash.commons.config.ConfigApplicationProperties;
import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingResponseDTO;
import com.hss.cryptohash.spec.CryptoHashStrategy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.time.Duration;
import java.time.Instant;

import static com.hss.cryptohash.commons.logging.LoggingConstants.LOG001;

@Slf4j
public class BcryptStrategyImpl implements CryptoHashStrategy {

    private final BCryptPasswordEncoder bcrypt;

    public BcryptStrategyImpl(ConfigApplicationProperties.BCryptProperties properties) {
        bcrypt = new BCryptPasswordEncoder(properties.strength());
    }

    @Override
    public EncryptionResponseDTO encrypt(String password) {
        var start = Instant.now();
        var encrypted = bcrypt.encode(password);
        var end = Instant.now();
        log.info(LOG001, "encrypt", "BCrypt", Duration.between(start, end).toMillis());
        return new EncryptionResponseDTO(encrypted);
    }

    @Override
    public PasswordMatchingResponseDTO matches(PasswordMatchingRequestDTO passwordMatchingRequestDTO) {
        var start = Instant.now();
        var match = bcrypt.matches(passwordMatchingRequestDTO.rawPassword(), passwordMatchingRequestDTO.encryptedPassword());
        var end = Instant.now();
        log.info(LOG001, "match", "BCrypt", Duration.between(start, end).toMillis());
        return new PasswordMatchingResponseDTO(match);
    }
}