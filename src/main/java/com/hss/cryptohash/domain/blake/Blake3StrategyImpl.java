package com.hss.cryptohash.domain.blake;

import com.hss.cryptohash.commons.config.ConfigApplicationProperties;
import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingResponseDTO;
import com.hss.cryptohash.spec.CryptoHashStrategy;
import com.hss.cryptohash.util.ByteComparator;
import lombok.extern.slf4j.Slf4j;

import java.time.Duration;
import java.time.Instant;

import static com.hss.cryptohash.commons.logging.LoggingConstants.LOG001;
import static org.apache.commons.codec.binary.Hex.encodeHexString;
import static org.apache.commons.codec.digest.Blake3.keyedHash;

@Slf4j
public class Blake3StrategyImpl implements CryptoHashStrategy {

    private final String key;

    public Blake3StrategyImpl(ConfigApplicationProperties.Blake3Properties properties) {
        this.key = properties.key();
    }

    @Override
    public EncryptionResponseDTO encrypt(String password) {
        var start = Instant.now();
        var encrypted = keyedHash(key.getBytes(), password.getBytes());
        var end = Instant.now();
        log.info(LOG001, "encrypt", "BLAKE3", Duration.between(start, end).toMillis());
        return new EncryptionResponseDTO(encodeHexString(encrypted));
    }

    @Override
    public PasswordMatchingResponseDTO matches(PasswordMatchingRequestDTO passwordMatchingRequestDTO) {
        var start = Instant.now();
        var password = keyedHash(key.getBytes(), passwordMatchingRequestDTO.rawPasswordBytes());
        var match = new ByteComparator().compare(encodeHexString(password).getBytes(), passwordMatchingRequestDTO.encryptedPasswordBytes());
        var end = Instant.now();
        log.info(LOG001, "match", "BLAKE3", Duration.between(start, end).toMillis());
        return new PasswordMatchingResponseDTO(match);
    }
}