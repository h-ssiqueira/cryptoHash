package com.hss.cryptohash.domain.sha;

import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingResponseDTO;
import com.hss.cryptohash.commons.exception.CryptoHashException;
import com.hss.cryptohash.spec.CryptoHashStrategy;
import com.hss.cryptohash.util.ByteComparator;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.time.Duration;
import java.time.Instant;

import static com.hss.cryptohash.commons.logging.LoggingConstants.LOG001;
import static org.apache.commons.codec.digest.DigestUtils.sha512_256Hex;

@Slf4j
@NoArgsConstructor
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
    public PasswordMatchingResponseDTO matches(PasswordMatchingRequestDTO passwordMatchingRequestDTO) {
        var start = Instant.now();
        var password = sha512_256Hex(passwordMatchingRequestDTO.rawPassword());
        var match = new ByteComparator().compare(password.getBytes(), passwordMatchingRequestDTO.encryptedPassword().getBytes());
        var end = Instant.now();
        log.info(LOG001, "match", "SHA512 256", Duration.between(start, end).toMillis());
        return new PasswordMatchingResponseDTO(match);
    }
}