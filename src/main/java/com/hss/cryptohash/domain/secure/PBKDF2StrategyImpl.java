package com.hss.cryptohash.domain.secure;

import com.hss.cryptohash.commons.config.ConfigApplicationProperties;
import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingResponseDTO;
import com.hss.cryptohash.spec.CryptoHashStrategy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm;

import java.time.Duration;
import java.time.Instant;

import static com.hss.cryptohash.commons.logging.LoggingConstants.LOG001;

@Slf4j
public class PBKDF2StrategyImpl implements CryptoHashStrategy {

    private final Pbkdf2PasswordEncoder pbkdf2;

    public PBKDF2StrategyImpl(ConfigApplicationProperties.PBKDF2Properties properties) {
        pbkdf2 = new Pbkdf2PasswordEncoder(properties.secret(), properties.saltLength(), properties.iterations(), SecretKeyFactoryAlgorithm.valueOf(properties.secretKeyFactoryAlgorithm()));
    }

    @Override
    public EncryptionResponseDTO encrypt(String password) {
        var start = Instant.now();
        var encrypted = pbkdf2.encode(password);
        var end = Instant.now();
        log.info(LOG001, "encrypt", "PBKDF2", Duration.between(start, end).toMillis());
        return new EncryptionResponseDTO(encrypted);
    }

    @Override
    public PasswordMatchingResponseDTO matches(PasswordMatchingRequestDTO passwordMatchingRequestDTO) {
        var start = Instant.now();
        var match = pbkdf2.matches(passwordMatchingRequestDTO.rawPassword(), passwordMatchingRequestDTO.encryptedPassword());
        var end = Instant.now();
        log.info(LOG001, "match", "PBKDF2", Duration.between(start, end).toMillis());
        return new PasswordMatchingResponseDTO(match);
    }
}