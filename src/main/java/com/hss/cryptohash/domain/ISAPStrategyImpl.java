package com.hss.cryptohash.domain;

import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingResponseDTO;
import com.hss.cryptohash.spec.CryptoHashStrategy;
import com.hss.cryptohash.util.ByteComparator;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.digests.ISAPDigest;

import java.time.Duration;
import java.time.Instant;

import static com.hss.cryptohash.commons.logging.LoggingConstants.LOG001;
import static org.bouncycastle.util.encoders.Hex.toHexString;

@Slf4j
@NoArgsConstructor
public class ISAPStrategyImpl implements CryptoHashStrategy {

    private final ISAPDigest isap = new ISAPDigest();

    @Override
    public EncryptionResponseDTO encrypt(String password) {
        var start = Instant.now();
        var encrypted = encrypt(password.getBytes());
        var end = Instant.now();
        log.info(LOG001, "encrypt", "ISAP", Duration.between(start, end).toMillis());
        return new EncryptionResponseDTO(encrypted);
    }

    @Override
    public PasswordMatchingResponseDTO matches(PasswordMatchingRequestDTO passwordMatchingRequestDTO) {
        var start = Instant.now();
        var match = new ByteComparator().compare(encrypt(passwordMatchingRequestDTO.rawPasswordBytes()).getBytes(), passwordMatchingRequestDTO.encryptedPasswordBytes());
        var end = Instant.now();
        log.info(LOG001, "match", "ISAP", Duration.between(start, end).toMillis());
        return new PasswordMatchingResponseDTO(match);
    }

    private String encrypt(byte[] text) {
        isap.update(text,0,text.length);
        var encrypted = new byte[isap.getDigestSize()];
        isap.doFinal(encrypted,0);
        return toHexString(encrypted);
    }
}