package com.hss.cryptohash.unit.domain.blake;

import com.hss.cryptohash.commons.config.ConfigApplicationProperties;
import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingResponseDTO;
import com.hss.cryptohash.domain.blake.Blake2spStrategyImpl;
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
class Blake2spStrategyImplTest extends CommonsTestConstants {

    @Mock
    private ConfigApplicationProperties.Blake2spProperties blake2spProperties;

    private Blake2spStrategyImpl blake2spStrategy;

    @BeforeEach
    void initMock() {
        when(blake2spProperties.key()).thenReturn(blake2spKey);
        blake2spStrategy = new Blake2spStrategyImpl(blake2spProperties);
    }

    @AfterEach
    void verifyMock() {
        verify(blake2spProperties).key();
    }

    @Test
    void encrypt() {
        var response = blake2spStrategy.encrypt(rawPassword);

        assertThat(response).isNotNull()
                .extracting(EncryptionResponseDTO::passwordEncrypted)
                .isEqualTo(blake2spEncryptedPassword);
    }

    @Test
    void matches() {
        assertThatNoException()
                .isThrownBy(() -> {
                    var response = blake2spStrategy.matches(new PasswordMatchingRequestDTO(rawPassword, blake2spEncryptedPassword));
                    assertThat(response).isNotNull()
                            .extracting(PasswordMatchingResponseDTO::match)
                            .isEqualTo(true);
                });
    }

    @Test
    void DoesNotMatches() {
        assertThatNoException().isThrownBy(() -> {
            var response = blake2spStrategy.matches(new PasswordMatchingRequestDTO(wrongPassword, blake2spEncryptedPassword));
            assertThat(response).isNotNull()
                    .extracting(PasswordMatchingResponseDTO::match)
                    .isEqualTo(false);
        });
    }
}