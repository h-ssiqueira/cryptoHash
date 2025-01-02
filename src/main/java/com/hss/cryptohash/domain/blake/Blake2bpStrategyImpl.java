package com.hss.cryptohash.domain.blake;

import com.hss.cryptohash.commons.config.ConfigApplicationProperties;
import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingResponseDTO;
import com.hss.cryptohash.spec.CryptoHashStrategy;
import com.hss.cryptohash.util.ByteComparator;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.digests.Blake2bpDigest;

import java.time.Duration;
import java.time.Instant;

import static com.hss.cryptohash.commons.logging.LoggingConstants.LOG001;
import static org.bouncycastle.util.encoders.Hex.toHexString;

@Slf4j
public class Blake2bpStrategyImpl implements CryptoHashStrategy {

    private final Blake2bpDigest blake2bpDigest;

    public Blake2bpStrategyImpl(ConfigApplicationProperties.Blake2bpProperties properties) {
        this.blake2bpDigest = new Blake2bpDigest(properties.key().getBytes());
    }

    @Override
    public EncryptionResponseDTO encrypt(String password) {
        var start = Instant.now();
        var encrypted = encrypt(password.getBytes());
        var end = Instant.now();
        log.info(LOG001, "encrypt", "BLAKE2BP", Duration.between(start, end).toMillis());
        return new EncryptionResponseDTO(encrypted);
    }

    @Override
    public PasswordMatchingResponseDTO matches(PasswordMatchingRequestDTO passwordMatchingRequestDTO) {
        var start = Instant.now();
        var match = new ByteComparator().compare(encrypt(passwordMatchingRequestDTO.rawPasswordBytes()).getBytes(), passwordMatchingRequestDTO.encryptedPasswordBytes());
        var end = Instant.now();
        log.info(LOG001, "match", "BLAKE2BP", Duration.between(start, end).toMillis());
        return new PasswordMatchingResponseDTO(match);
    }

    private String encrypt(byte[] text) {
        blake2bpDigest.update(text,0,text.length);
        var encrypted = new byte[blake2bpDigest.getDigestSize()];
        blake2bpDigest.doFinal(encrypted,0);
        return toHexString(encrypted);
    }
}