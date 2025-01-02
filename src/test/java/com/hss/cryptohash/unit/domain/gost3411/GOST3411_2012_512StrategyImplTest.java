package com.hss.cryptohash.unit.domain.gost3411;

import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingResponseDTO;
import com.hss.cryptohash.domain.gost3411.GOST3411_2012_512StrategyImpl;
import com.hss.cryptohash.unit.CommonsTestConstants;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

class GOST3411_2012_512StrategyImplTest extends CommonsTestConstants {

    private final GOST3411_2012_512StrategyImpl gost3411_2012_512Strategy = new GOST3411_2012_512StrategyImpl();

    @Test
    void encrypt() {
        var response = gost3411_2012_512Strategy.encrypt(rawPassword);

        assertThat(response).isNotNull()
                .extracting(EncryptionResponseDTO::passwordEncrypted)
                .isEqualTo(gost3411_2012_512EncryptedPassword);
    }

    @Test
    void matches() {
        assertThatNoException()
                .isThrownBy(() -> {
                    var response = gost3411_2012_512Strategy.matches(new PasswordMatchingRequestDTO(rawPassword, gost3411_2012_512EncryptedPassword));
                    assertThat(response).isNotNull()
                            .extracting(PasswordMatchingResponseDTO::match)
                            .isEqualTo(true);
                });
    }

    @Test
    void DoesNotMatches() {
        assertThatNoException().isThrownBy(() -> {
            var response = gost3411_2012_512Strategy.matches(new PasswordMatchingRequestDTO(wrongPassword, gost3411_2012_512EncryptedPassword));
            assertThat(response).isNotNull()
                    .extracting(PasswordMatchingResponseDTO::match)
                    .isEqualTo(false);
        });
    }
}