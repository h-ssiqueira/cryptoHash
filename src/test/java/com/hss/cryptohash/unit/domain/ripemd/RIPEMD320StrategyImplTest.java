package com.hss.cryptohash.unit.domain.ripemd;

import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingResponseDTO;
import com.hss.cryptohash.domain.ripemd.RIPEMD320StrategyImpl;
import com.hss.cryptohash.unit.CommonsTestConstants;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

class RIPEMD320StrategyImplTest extends CommonsTestConstants {

    private final RIPEMD320StrategyImpl ripemd320Strategy = new RIPEMD320StrategyImpl();

    @Test
    void encrypt() {
        var response = ripemd320Strategy.encrypt(rawPassword);

        assertThat(response).isNotNull()
                .extracting(EncryptionResponseDTO::passwordEncrypted)
                .isEqualTo(RIPEMD320EncryptedPassword);
    }

    @Test
    void matches() {
        assertThatNoException()
                .isThrownBy(() -> {
                    var response = ripemd320Strategy.matches(new PasswordMatchingRequestDTO(rawPassword, RIPEMD320EncryptedPassword));
                    assertThat(response).isNotNull()
                            .extracting(PasswordMatchingResponseDTO::match)
                            .isEqualTo(true);
                });
    }

    @Test
    void DoesNotMatches() {
        assertThatNoException().isThrownBy(() -> {
            var response = ripemd320Strategy.matches(new PasswordMatchingRequestDTO(wrongPassword, RIPEMD320EncryptedPassword));
            assertThat(response).isNotNull()
                    .extracting(PasswordMatchingResponseDTO::match)
                    .isEqualTo(false);
        });
    }
}