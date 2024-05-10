package com.hss.cryptohash.domain.secure;

import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.MatchedResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingDTO;
import com.hss.cryptohash.spec.CryptoHashStrategy;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

import java.time.Duration;
import java.time.Instant;

import static com.hss.cryptohash.commons.logging.LoggingConstants.LOG001;

@Slf4j
@ApplicationScoped
public class ScryptStrategyImpl implements CryptoHashStrategy {

    @ConfigProperty(name = "hash.scrypt.cpuCost")
    private int cpuCost;
    @ConfigProperty(name = "hash.scrypt.memoryCost")
    private int memoryCost;
    @ConfigProperty(name = "hash.scrypt.parallelization")
    private int parallelization;
    @ConfigProperty(name = "hash.scrypt.keyLength")
    private int keyLength;
    @ConfigProperty(name = "hash.scrypt.saltLength")
    private int saltLength;

    private SCryptPasswordEncoder scrypt;

    @Inject
    @PostConstruct
    public void init() {
        scrypt = new SCryptPasswordEncoder(cpuCost, memoryCost, parallelization, keyLength, saltLength);
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
    public MatchedResponseDTO matches(PasswordMatchingDTO passwordMatchingDTO) {
        var start = Instant.now();
        var match = scrypt.matches(passwordMatchingDTO.rawPassword(), passwordMatchingDTO.encryptedPassword());
        var end = Instant.now();
        log.info(LOG001, "match", "SCrypt", Duration.between(start, end).toMillis());
        return new MatchedResponseDTO(match);
    }
}
