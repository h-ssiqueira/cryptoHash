package com.hss.cryptohash.unit.domain.ripemd;

import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingResponseDTO;
import com.hss.cryptohash.domain.ripemd.RIPEMD160StrategyImpl;
import com.hss.cryptohash.unit.CommonsTestConstants;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

class RIPEMD160StrategyImplTest extends CommonsTestConstants {

    private final RIPEMD160StrategyImpl ripemd160Strategy = new RIPEMD160StrategyImpl();

    @Test
    void encrypt() {
        var response = ripemd160Strategy.encrypt(rawPassword);

        assertThat(response).isNotNull()
                .extracting(EncryptionResponseDTO::passwordEncrypted)
                .isEqualTo(RIPEMD160EncryptedPassword);
    }

    @Test
    void matches() {
        assertThatNoException()
                .isThrownBy(() -> {
                    var response = ripemd160Strategy.matches(new PasswordMatchingRequestDTO(rawPassword, RIPEMD160EncryptedPassword));
                    assertThat(response).isNotNull()
                            .extracting(PasswordMatchingResponseDTO::match)
                            .isEqualTo(true);
                });
    }

    @Test
    void DoesNotMatches() {
        assertThatNoException().isThrownBy(() -> {
            var response = ripemd160Strategy.matches(new PasswordMatchingRequestDTO(wrongPassword, RIPEMD160EncryptedPassword));
            assertThat(response).isNotNull()
                    .extracting(PasswordMatchingResponseDTO::match)
                    .isEqualTo(false);
        });
    }
}