package com.hss.cryptohash.unit.domain;

import com.hss.cryptohash.commons.config.ConfigApplicationProperties;
import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingResponseDTO;
import com.hss.cryptohash.domain.DSTU7564StrategyImpl;
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
class DSTU7564StrategyImplTest extends CommonsTestConstants {

    @Mock
    private ConfigApplicationProperties.DSTU7564Properties dstu7564Properties;

    private DSTU7564StrategyImpl DSTU7564Strategy;

    @BeforeEach
    void initMock() {
        when(dstu7564Properties.hashSize()).thenReturn(dstu7564HashSize);
        DSTU7564Strategy = new DSTU7564StrategyImpl(dstu7564Properties);
    }

    @AfterEach
    void verifyMock() {
        verify(dstu7564Properties).hashSize();
    }

    @Test
    void encrypt() {
        var response = DSTU7564Strategy.encrypt(rawPassword);

        assertThat(response).isNotNull()
                .extracting(EncryptionResponseDTO::passwordEncrypted)
                .isEqualTo(dstu7564EncryptedPassword);
    }

    @Test
    void matches() {
        assertThatNoException()
                .isThrownBy(() -> {
                    var response = DSTU7564Strategy.matches(new PasswordMatchingRequestDTO(rawPassword, dstu7564EncryptedPassword));
                    assertThat(response).isNotNull()
                            .extracting(PasswordMatchingResponseDTO::match)
                            .isEqualTo(true);
                });
    }

    @Test
    void DoesNotMatches() {
        assertThatNoException().isThrownBy(() -> {
            var response = DSTU7564Strategy.matches(new PasswordMatchingRequestDTO(wrongPassword, dstu7564EncryptedPassword));
            assertThat(response).isNotNull()
                    .extracting(PasswordMatchingResponseDTO::match)
                    .isEqualTo(false);
        });
    }
}