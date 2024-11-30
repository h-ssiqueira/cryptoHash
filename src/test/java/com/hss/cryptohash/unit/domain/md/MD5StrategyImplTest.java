package com.hss.cryptohash.unit.domain.md;

import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.exception.CryptoHashException;
import com.hss.cryptohash.domain.md.MD5StrategyImpl;
import com.hss.cryptohash.unit.CommonsTestConstants;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MD5StrategyImplTest extends CommonsTestConstants {

    private final MD5StrategyImpl md5Strategy = new MD5StrategyImpl();

    @Test
    void encrypt() {
        var response = md5Strategy.encrypt(rawPassword);

        assertThat(response).isNotNull()
                .extracting(EncryptionResponseDTO::passwordEncrypted)
                .isEqualTo(md5EncryptedPassword);
    }

    @Test
    void matches() {
        assertThatNoException().isThrownBy(() -> md5Strategy.matches(new PasswordMatchingRequestDTO(rawPassword, md5EncryptedPassword)));
    }

    @Test
    void DoesNotMatches() {
        var request = new PasswordMatchingRequestDTO(wrongPassword, md5EncryptedPassword);
        assertThatThrownBy(() -> md5Strategy.matches(request))
                .isInstanceOf(CryptoHashException.class)
                .hasMessage("Invalid password!");
    }
}