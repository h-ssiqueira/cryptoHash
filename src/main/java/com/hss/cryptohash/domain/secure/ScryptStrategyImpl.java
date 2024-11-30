package com.hss.cryptohash.domain.secure;

import com.hss.cryptohash.commons.config.ConfigApplicationProperties;
import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.exception.CryptoHashException;
import com.hss.cryptohash.spec.CryptoHashStrategy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

import java.time.Duration;
import java.time.Instant;

import static com.hss.cryptohash.commons.logging.LoggingConstants.LOG001;

@Slf4j
public class ScryptStrategyImpl implements CryptoHashStrategy {

    private final SCryptPasswordEncoder scrypt;

    public ScryptStrategyImpl(ConfigApplicationProperties.SCryptProperties properties) {
        scrypt = new SCryptPasswordEncoder(properties.cpuCost(), properties.memoryCost(), properties.parallelization(), properties.keyLength(), properties.saltLength());
    }

    @Override
    public EncryptionResponseDTO encrypt(String password) {
        var start = Instant.now();
        var encrypted = scrypt.encode(password);
        var end = Instant.now();
        log.info(LOG001, "encrypt", "SCrypt", Duration.between(start, end).toMillis());
        return new EncryptionResponseDTO(encrypted);
    }

    @Override
    public void matches(PasswordMatchingRequestDTO passwordMatchingRequestDTO) {
        var start = Instant.now();
        var match = scrypt.matches(passwordMatchingRequestDTO.rawPassword(), passwordMatchingRequestDTO.encryptedPassword());
        var end = Instant.now();
        log.info(LOG001, "match", "SCrypt", Duration.between(start, end).toMillis());
        if (!match) {
            throw new CryptoHashException("Invalid password!");
        }
    }
}