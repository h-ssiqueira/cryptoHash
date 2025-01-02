package com.hss.cryptohash.unit.domain;

import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingResponseDTO;
import com.hss.cryptohash.domain.PhotonBeetleStrategyImpl;
import com.hss.cryptohash.unit.CommonsTestConstants;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

class PhotonBeetleStrategyImplTest extends CommonsTestConstants {

    private final PhotonBeetleStrategyImpl photonBeetleStrategy = new PhotonBeetleStrategyImpl();

    @Test
    void encrypt() {
        var response = photonBeetleStrategy.encrypt(rawPassword);

        assertThat(response).isNotNull()
                .extracting(EncryptionResponseDTO::passwordEncrypted)
                .isEqualTo(photonBeetleEncryptedPassword);
    }

    @Test
    void matches() {
        assertThatNoException()
                .isThrownBy(() -> {
                    var response = photonBeetleStrategy.matches(new PasswordMatchingRequestDTO(rawPassword, photonBeetleEncryptedPassword));
                    assertThat(response).isNotNull()
                            .extracting(PasswordMatchingResponseDTO::match)
                            .isEqualTo(true);
                });
    }

    @Test
    void DoesNotMatches() {
        assertThatNoException().isThrownBy(() -> {
            var response = photonBeetleStrategy.matches(new PasswordMatchingRequestDTO(wrongPassword, photonBeetleEncryptedPassword));
            assertThat(response).isNotNull()
                    .extracting(PasswordMatchingResponseDTO::match)
                    .isEqualTo(false);
        });
    }
}