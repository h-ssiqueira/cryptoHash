package com.hss.cryptohash.unit.domain;

import com.hss.cryptohash.commons.config.ConfigApplicationProperties;
import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingResponseDTO;
import com.hss.cryptohash.domain.SkeinStrategyImpl;
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
class SkeinStrategyImplTest extends CommonsTestConstants {

    @Mock
    private ConfigApplicationProperties.SkeinProperties skeinProperties;

    private SkeinStrategyImpl skeinStrategy;

    @BeforeEach
    void initMock() {
        when(skeinProperties.outputSize()).thenReturn(skeinOutputSize);
        when(skeinProperties.blockSize()).thenReturn(skeinBlockSize);
        skeinStrategy = new SkeinStrategyImpl(skeinProperties);
    }

    @AfterEach
    void verifyMock() {
        verify(skeinProperties).outputSize();
        verify(skeinProperties).blockSize();
    }

    @Test
    void encrypt() {
        var response = skeinStrategy.encrypt(rawPassword);

        assertThat(response).isNotNull()
                .extracting(EncryptionResponseDTO::passwordEncrypted)
                .isEqualTo(skeinEncryptedPassword);
    }

    @Test
    void matches() {
        assertThatNoException()
                .isThrownBy(() -> {
                    var response = skeinStrategy.matches(new PasswordMatchingRequestDTO(rawPassword, skeinEncryptedPassword));
                    assertThat(response).isNotNull()
                            .extracting(PasswordMatchingResponseDTO::match)
                            .isEqualTo(true);
                });
    }

    @Test
    void DoesNotMatches() {
        assertThatNoException().isThrownBy(() -> {
            var response = skeinStrategy.matches(new PasswordMatchingRequestDTO(wrongPassword, skeinEncryptedPassword));
            assertThat(response).isNotNull()
                    .extracting(PasswordMatchingResponseDTO::match)
                    .isEqualTo(false);
        });
    }
}