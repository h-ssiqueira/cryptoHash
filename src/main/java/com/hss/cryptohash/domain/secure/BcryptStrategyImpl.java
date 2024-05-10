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
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.time.Duration;
import java.time.Instant;

import static com.hss.cryptohash.commons.logging.LoggingConstants.LOG001;

@Slf4j
@ApplicationScoped
public class BcryptStrategyImpl implements CryptoHashStrategy {

    private BCryptPasswordEncoder bcrypt;

    @Inject
    @PostConstruct
    public void init(@ConfigProperty(name = "hash.bcrypt.strength") String strength) {
        bcrypt = new BCryptPasswordEncoder(Integer.parseInt(strength));
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
    public MatchedResponseDTO matches(PasswordMatchingDTO passwordMatchingDTO) {
        var start = Instant.now();
        var match = bcrypt.matches(passwordMatchingDTO.rawPassword(), passwordMatchingDTO.encryptedPassword());
        var end = Instant.now();
        log.info(LOG001, "match", "BCrypt", Duration.between(start, end).toMillis());
        return new MatchedResponseDTO(match);
    }
}
