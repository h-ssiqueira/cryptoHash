package com.hss.cryptohash.domain.shake;

import com.hss.cryptohash.commons.config.ConfigApplicationProperties;
import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingResponseDTO;
import com.hss.cryptohash.spec.CryptoHashStrategy;
import com.hss.cryptohash.util.ByteComparator;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.digests.CSHAKEDigest;

import java.time.Duration;
import java.time.Instant;

import static com.hss.cryptohash.commons.logging.LoggingConstants.LOG001;
import static org.bouncycastle.util.encoders.Hex.toHexString;

@Slf4j
public class CSHAKEStrategyImpl implements CryptoHashStrategy {

    private final CSHAKEDigest cshake;

    public CSHAKEStrategyImpl(ConfigApplicationProperties.CSHAKEProperties properties) {
        this.cshake = new CSHAKEDigest(properties.bitStrength(),null,null);
    }

    @Override
    public EncryptionResponseDTO encrypt(String password) {
        var start = Instant.now();
        var encrypted = encrypt(password.getBytes());
        var end = Instant.now();
        log.info(LOG001, "encrypt", "CSHAKE", Duration.between(start, end).toMillis());
        return new EncryptionResponseDTO(encrypted);
    }

    @Override
    public PasswordMatchingResponseDTO matches(PasswordMatchingRequestDTO passwordMatchingRequestDTO) {
        var start = Instant.now();
        var match = new ByteComparator().compare(encrypt(passwordMatchingRequestDTO.rawPasswordBytes()).getBytes(), passwordMatchingRequestDTO.encryptedPasswordBytes());
        var end = Instant.now();
        log.info(LOG001, "match", "CSHAKE", Duration.between(start, end).toMillis());
        return new PasswordMatchingResponseDTO(match);
    }

    private String encrypt(byte[] text) {
        cshake.update(text,0,text.length);
        var encrypted = new byte[cshake.getDigestSize()];
        cshake.doFinal(encrypted,0);
        return toHexString(encrypted);
    }
}