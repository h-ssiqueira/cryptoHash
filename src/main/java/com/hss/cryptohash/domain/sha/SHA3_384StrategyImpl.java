package com.hss.cryptohash.domain.sha;

import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.MatchedResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingDTO;
import com.hss.cryptohash.spec.CryptoHashStrategy;
import com.hss.cryptohash.util.ByteComparator;
import lombok.extern.slf4j.Slf4j;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;

import static com.hss.cryptohash.commons.logging.LoggingConstants.LOG001;
import static org.apache.commons.codec.digest.DigestUtils.sha3_384;

@Slf4j
public class SHA3_384StrategyImpl implements CryptoHashStrategy {

    @Override
    public EncryptionResponseDTO encrypt(String password) {
        var start = Instant.now();
        var encrypted = sha3_384(password);
        var end = Instant.now();
        log.info(LOG001, "encrypt", "SHA3 384", Duration.between(start, end).toMillis());
        return new EncryptionResponseDTO(Arrays.toString(encrypted));
    }

    @Override
    public MatchedResponseDTO matches(PasswordMatchingDTO passwordMatchingDTO) {
        var start = Instant.now();
        var password = sha3_384(passwordMatchingDTO.rawPassword());
        var match = new ByteComparator().compare(password, passwordMatchingDTO.encryptedPassword().getBytes());
        var end = Instant.now();
        log.info(LOG001, "match", "SHA3 384", Duration.between(start, end).toMillis());
        return new MatchedResponseDTO(match == 0);
    }
}
