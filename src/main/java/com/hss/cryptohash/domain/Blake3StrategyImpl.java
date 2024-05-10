package com.hss.cryptohash.domain;

import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.MatchedResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingDTO;
import com.hss.cryptohash.spec.CryptoHashStrategy;
import com.hss.cryptohash.util.ByteComparator;
import jakarta.enterprise.context.ApplicationScoped;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Hex;
import org.eclipse.microprofile.config.ConfigProvider;

import java.time.Duration;
import java.time.Instant;

import static com.hss.cryptohash.commons.logging.LoggingConstants.LOG001;
import static org.apache.commons.codec.digest.Blake3.keyedHash;

@Slf4j
@ApplicationScoped
public class Blake3StrategyImpl implements CryptoHashStrategy {

    private final byte[] key = ConfigProvider.getConfig().getValue("hash.blake3.key",String.class).getBytes();

    @Override
    public EncryptionResponseDTO encrypt(String password) {
        var start = Instant.now();
        var encrypted = keyedHash(key, password.getBytes());
        var end = Instant.now();
        log.info(LOG001, "encrypt", "BLAKE3", Duration.between(start, end).toMillis());
        return new EncryptionResponseDTO(Hex.encodeHexString(encrypted));
    }

    @Override
    public MatchedResponseDTO matches(PasswordMatchingDTO passwordMatchingDTO) {
        var start = Instant.now();
        var password = keyedHash(key, passwordMatchingDTO.rawPassword().getBytes());
        var match = new ByteComparator().compare(Hex.encodeHexString(password).getBytes(), passwordMatchingDTO.encryptedPassword().getBytes());
        var end = Instant.now();
        log.info(LOG001, "match", "BLAKE3", Duration.between(start, end).toMillis());
        return new MatchedResponseDTO(match == 0);
    }
}
