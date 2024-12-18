package com.hss.cryptohash.unit.domain.shake;

import com.hss.cryptohash.commons.config.ConfigApplicationProperties;
import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingResponseDTO;
import com.hss.cryptohash.domain.shake.CSHAKEStrategyImpl;
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
class CSHAKEStrategyImplTest extends CommonsTestConstants {

    @Mock
    private ConfigApplicationProperties.CSHAKEProperties cShakeProperties;

    private CSHAKEStrategyImpl cshakeStrategy;

    @BeforeEach
    void initMock() {
        when(cShakeProperties.bitStrength()).thenReturn(cshakeBitStrength);
        cshakeStrategy = new CSHAKEStrategyImpl(cShakeProperties);
    }

    @AfterEach
    void verifyMock() {
        verify(cShakeProperties).bitStrength();
    }

    @Test
    void encrypt() {
        var response = cshakeStrategy.encrypt(rawPassword);

        assertThat(response).isNotNull()
                .extracting(EncryptionResponseDTO::passwordEncrypted)
                .isEqualTo(cshakeEncryptedPassword);
    }

    @Test
    void matches() {
        assertThatNoException()
                .isThrownBy(() -> {
                    var response = cshakeStrategy.matches(new PasswordMatchingRequestDTO(rawPassword, cshakeEncryptedPassword));
                    assertThat(response).isNotNull()
                            .extracting(PasswordMatchingResponseDTO::match)
                            .isEqualTo(true);
                });
    }

    @Test
    void DoesNotMatches() {
        assertThatNoException().isThrownBy(() -> {
            var response = cshakeStrategy.matches(new PasswordMatchingRequestDTO(wrongPassword, cshakeEncryptedPassword));
            assertThat(response).isNotNull()
                    .extracting(PasswordMatchingResponseDTO::match)
                    .isEqualTo(false);
        });
    }
}