package com.hss.cryptohash.unit.domain;

import com.hss.cryptohash.commons.config.ConfigApplicationProperties;
import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingResponseDTO;
import com.hss.cryptohash.domain.AsconStrategyImpl;
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
class AsconStrategyImplTest extends CommonsTestConstants {

    @Mock
    private ConfigApplicationProperties.AsconProperties asconProperties;

    private AsconStrategyImpl asconStrategy;

    @BeforeEach
    void initMock() {
        when(asconProperties.algorithm()).thenReturn(asconAlgorithm);
        asconStrategy = new AsconStrategyImpl(asconProperties);
    }

    @AfterEach
    void verifyMock() {
        verify(asconProperties).algorithm();
    }

    @Test
    void encrypt() {
        var response = asconStrategy.encrypt(rawPassword);

        assertThat(response).isNotNull()
                .extracting(EncryptionResponseDTO::passwordEncrypted)
                .isEqualTo(asconEncryptedPassword);
    }

    @Test
    void matches() {
        assertThatNoException()
                .isThrownBy(() -> {
                    var response = asconStrategy.matches(new PasswordMatchingRequestDTO(rawPassword, asconEncryptedPassword));
                    assertThat(response).isNotNull()
                            .extracting(PasswordMatchingResponseDTO::match)
                            .isEqualTo(true);
                });
    }

    @Test
    void DoesNotMatches() {
        assertThatNoException().isThrownBy(() -> {
            var response = asconStrategy.matches(new PasswordMatchingRequestDTO(wrongPassword, asconEncryptedPassword));
            assertThat(response).isNotNull()
                    .extracting(PasswordMatchingResponseDTO::match)
                    .isEqualTo(false);
        });
    }
}