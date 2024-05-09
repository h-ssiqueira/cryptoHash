package com.hss.cryptohash.domain.md5;

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
import static org.apache.commons.codec.digest.DigestUtils.md5;

@Slf4j
public class MD5StrategyImpl implements CryptoHashStrategy {

    @Override
    public EncryptionResponseDTO encrypt(String password) {
        var start = Instant.now();
        var encrypted = md5(password);
        var end = Instant.now();
        log.info(LOG001, "encrypt", "MD5", Duration.between(start, end).toMillis());
        return new EncryptionResponseDTO(Arrays.toString(encrypted));
    }

    @Override
    public MatchedResponseDTO matches(PasswordMatchingDTO passwordMatchingDTO) {
        var start = Instant.now();
        var password = md5(passwordMatchingDTO.rawPassword());
        var match = new ByteComparator().compare(password, passwordMatchingDTO.encryptedPassword().getBytes());
        var end = Instant.now();
        log.info(LOG001, "match", "MD5", Duration.between(start, end).toMillis());
        return new MatchedResponseDTO(match == 0);
    }
}
