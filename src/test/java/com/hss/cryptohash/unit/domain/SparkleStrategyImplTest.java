package com.hss.cryptohash.unit.domain;

import com.hss.cryptohash.commons.config.ConfigApplicationProperties;
import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingResponseDTO;
import com.hss.cryptohash.domain.SparkleStrategyImpl;
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
class SparkleStrategyImplTest extends CommonsTestConstants {

    @Mock
    private ConfigApplicationProperties.SparkleProperties sparkleProperties;

    private SparkleStrategyImpl sparkleStrategy;

    @BeforeEach
    void initMock() {
        when(sparkleProperties.param()).thenReturn(sparkleParam);
        sparkleStrategy = new SparkleStrategyImpl(sparkleProperties);
    }

    @AfterEach
    void verifyMock() {
        verify(sparkleProperties).param();
    }

    @Test
    void encrypt() {
        var response = sparkleStrategy.encrypt(rawPassword);

        assertThat(response).isNotNull()
                .extracting(EncryptionResponseDTO::passwordEncrypted)
                .isEqualTo(sparkleEncryptedPassword);
    }

    @Test
    void matches() {
        assertThatNoException()
                .isThrownBy(() -> {
                    var response = sparkleStrategy.matches(new PasswordMatchingRequestDTO(rawPassword, sparkleEncryptedPassword));
                    assertThat(response).isNotNull()
                            .extracting(PasswordMatchingResponseDTO::match)
                            .isEqualTo(true);
                });
    }

    @Test
    void DoesNotMatches() {
        assertThatNoException().isThrownBy(() -> {
            var response = sparkleStrategy.matches(new PasswordMatchingRequestDTO(wrongPassword, sparkleEncryptedPassword));
            assertThat(response).isNotNull()
                    .extracting(PasswordMatchingResponseDTO::match)
                    .isEqualTo(false);
        });
    }
}