package com.hss.cryptohash.unit.domain.blake;

import com.hss.cryptohash.commons.config.ConfigApplicationProperties;
import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingResponseDTO;
import com.hss.cryptohash.domain.blake.Blake2bpStrategyImpl;
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
class Blake2bpStrategyImplTest extends CommonsTestConstants {

    @Mock
    private ConfigApplicationProperties.Blake2bpProperties blake2bpProperties;

    private Blake2bpStrategyImpl blake2bpStrategy;

    @BeforeEach
    void initMock() {
        when(blake2bpProperties.key()).thenReturn(blake2bpKey);
        blake2bpStrategy = new Blake2bpStrategyImpl(blake2bpProperties);
    }

    @AfterEach
    void verifyMock() {
        verify(blake2bpProperties).key();
    }

    @Test
    void encrypt() {
        var response = blake2bpStrategy.encrypt(rawPassword);

        assertThat(response).isNotNull()
                .extracting(EncryptionResponseDTO::passwordEncrypted)
                .isEqualTo(blake2bpEncryptedPassword);
    }

    @Test
    void matches() {
        assertThatNoException()
                .isThrownBy(() -> {
                    var response = blake2bpStrategy.matches(new PasswordMatchingRequestDTO(rawPassword, blake2bpEncryptedPassword));
                    assertThat(response).isNotNull()
                            .extracting(PasswordMatchingResponseDTO::match)
                            .isEqualTo(true);
                });
    }

    @Test
    void DoesNotMatches() {
        assertThatNoException().isThrownBy(() -> {
            var response = blake2bpStrategy.matches(new PasswordMatchingRequestDTO(wrongPassword, blake2bpEncryptedPassword));
            assertThat(response).isNotNull()
                    .extracting(PasswordMatchingResponseDTO::match)
                    .isEqualTo(false);
        });
    }
}