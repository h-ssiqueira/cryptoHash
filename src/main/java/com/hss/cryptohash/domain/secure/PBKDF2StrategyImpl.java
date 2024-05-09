package com.hss.cryptohash.domain.secure;

import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.MatchedResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingDTO;
import com.hss.cryptohash.spec.CryptoHashStrategy;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm;

import java.time.Duration;
import java.time.Instant;

import static com.hss.cryptohash.commons.logging.LoggingConstants.LOG001;

@Slf4j
public class PBKDF2StrategyImpl implements CryptoHashStrategy {

    @ConfigProperty(name = "hash.pbkd2.secret")
    private CharSequence secret;
    @ConfigProperty(name = "hash.pbkd2.saltLength")
    private int saltLength;
    @ConfigProperty(name = "hash.pbkd2.iterations")
    private int iterations;
    @ConfigProperty(name = "hash.pbkd2.secretKeyFactoryAlgorithm")
    private SecretKeyFactoryAlgorithm secretKeyFactoryAlgorithm;

    private final Pbkdf2PasswordEncoder pbkd2 = new Pbkdf2PasswordEncoder(secret, saltLength, iterations, secretKeyFactoryAlgorithm);

    @Override
    public EncryptionResponseDTO encrypt(String password) {
        var start = Instant.now();
        var encrypted = pbkd2.encode(password);
        var end = Instant.now();
        log.info(LOG001, "encrypt", "PBKDF2", Duration.between(start, end).toMillis());
        return new EncryptionResponseDTO(encrypted);
    }

    @Override
    public MatchedResponseDTO matches(PasswordMatchingDTO passwordMatchingDTO) {
        var start = Instant.now();
        var match = pbkd2.matches(passwordMatchingDTO.rawPassword(), passwordMatchingDTO.encryptedPassword());
        var end = Instant.now();
        log.info(LOG001, "match", "PBKDF2", Duration.between(start, end).toMillis());
        return new MatchedResponseDTO(match);
    }
}
