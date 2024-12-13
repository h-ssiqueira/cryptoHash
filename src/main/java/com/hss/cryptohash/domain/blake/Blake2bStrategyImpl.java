package com.hss.cryptohash.domain.blake;

import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingResponseDTO;
import com.hss.cryptohash.spec.CryptoHashStrategy;
import com.hss.cryptohash.util.ByteComparator;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.digests.Blake2bDigest;

import java.time.Duration;
import java.time.Instant;

import static com.hss.cryptohash.commons.logging.LoggingConstants.LOG001;
import static org.bouncycastle.util.encoders.Hex.toHexString;

@Slf4j
@NoArgsConstructor
public class Blake2bStrategyImpl implements CryptoHashStrategy {

    private final Blake2bDigest blake2bDigest = new Blake2bDigest();

    @Override
    public EncryptionResponseDTO encrypt(String password) {
        var start = Instant.now();
        var encrypted = encrypt(password.getBytes());
        var end = Instant.now();
        log.info(LOG001, "encrypt", "BLAKE2B", Duration.between(start, end).toMillis());
        return new EncryptionResponseDTO(toHexString(encrypted));
    }

    @Override
    public PasswordMatchingResponseDTO matches(PasswordMatchingRequestDTO passwordMatchingRequestDTO) {
        var start = Instant.now();
        var match = new ByteComparator().compare(toHexString(encrypt(passwordMatchingRequestDTO.rawPasswordBytes())).getBytes(), passwordMatchingRequestDTO.encryptedPasswordBytes());
        var end = Instant.now();
        log.info(LOG001, "match", "BLAKE2B", Duration.between(start, end).toMillis());
        return new PasswordMatchingResponseDTO(match);
    }

    private byte[] encrypt(byte[] text) {
        blake2bDigest.update(text,0,text.length);
        var encrypted = new byte[blake2bDigest.getDigestSize()];
        blake2bDigest.doFinal(encrypted,0);
        return encrypted;
    }
}