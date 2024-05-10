package com.hss.cryptohash.domain.sha;

import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.MatchedResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingDTO;
import com.hss.cryptohash.spec.CryptoHashStrategy;
import com.hss.cryptohash.util.ByteComparator;
import jakarta.enterprise.context.ApplicationScoped;
import lombok.extern.slf4j.Slf4j;

import java.time.Duration;
import java.time.Instant;

import static com.hss.cryptohash.commons.logging.LoggingConstants.LOG001;
import static org.apache.commons.codec.digest.DigestUtils.sha512_256Hex;

@Slf4j
@ApplicationScoped
public class SHA512_256StrategyImpl implements CryptoHashStrategy {

    @Override
    public EncryptionResponseDTO encrypt(String password) {
        var start = Instant.now();
        var encrypted = sha512_256Hex(password);
        var end = Instant.now();
        log.info(LOG001, "encrypt", "SHA512 256", Duration.between(start, end).toMillis());
        return new EncryptionResponseDTO(encrypted);
    }

    @Override
    public MatchedResponseDTO matches(PasswordMatchingDTO passwordMatchingDTO) {
        var start = Instant.now();
        var password = sha512_256Hex(passwordMatchingDTO.rawPassword());
        var match = new ByteComparator().compare(password.getBytes(), passwordMatchingDTO.encryptedPassword().getBytes());
        var end = Instant.now();
        log.info(LOG001, "match", "SHA512 256", Duration.between(start, end).toMillis());
        return new MatchedResponseDTO(match == 0);
    }
}
