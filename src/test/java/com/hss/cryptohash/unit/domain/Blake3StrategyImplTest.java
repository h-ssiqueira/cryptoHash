package com.hss.cryptohash.unit.domain;

import com.hss.cryptohash.commons.config.ConfigApplicationProperties;
import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingResponseDTO;
import com.hss.cryptohash.domain.Blake3StrategyImpl;
import com.hss.cryptohash.unit.CommonsTestConstants;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class Blake3StrategyImplTest extends CommonsTestConstants {

    @Mock
    private ConfigApplicationProperties.Blake3Properties blake3Properties;

    private Blake3StrategyImpl blake3Strategy;

    @BeforeEach
    void initMock() {
        when(blake3Properties.key()).thenReturn(blake3Key);
        blake3Strategy = new Blake3StrategyImpl(blake3Properties);
    }

    @AfterEach
    void verifyMock() {
        verify(blake3Properties).key();
    }

    @Test
    void encrypt() {
        var response = blake3Strategy.encrypt(rawPassword);

        assertThat(response).isNotNull()
                .extracting(EncryptionResponseDTO::passwordEncrypted)
                .isEqualTo(blake3EncryptedPassword);
    }

    @Test
    void matches() {
        assertThatNoException()
                .isThrownBy(() -> {
                    var response = blake3Strategy.matches(new PasswordMatchingRequestDTO(rawPassword, blake3EncryptedPassword));
                    assertThat(response).isNotNull()
                            .extracting(PasswordMatchingResponseDTO::match)
                            .isEqualTo(true);
                });
    }

    @Test
    void DoesNotMatches() {
        assertThatNoException().isThrownBy(() -> {
            var response = blake3Strategy.matches(new PasswordMatchingRequestDTO(wrongPassword, blake3EncryptedPassword));
            assertThat(response).isNotNull()
                    .extracting(PasswordMatchingResponseDTO::match)
                    .isEqualTo(false);
        });
    }
}