package com.hss.cryptohash.unit.domain.secure;

import com.hss.cryptohash.commons.config.ConfigApplicationProperties;
import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingResponseDTO;
import com.hss.cryptohash.domain.secure.PBKDF2StrategyImpl;
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
class PBKDF2StrategyImplTest extends CommonsTestConstants {

    @Mock
    private ConfigApplicationProperties.PBKDF2Properties pbkdf2Properties;

    private PBKDF2StrategyImpl pbkdf2Strategy;

    @BeforeEach
    void initMock() {
        when(pbkdf2Properties.secret()).thenReturn(pbkdf2Secret);
        when(pbkdf2Properties.iterations()).thenReturn(pbkdf2Iterations);
        when(pbkdf2Properties.saltLength()).thenReturn(pbkdf2SaltLength);
        when(pbkdf2Properties.secretKeyFactoryAlgorithm()).thenReturn(pbkdf2SecretKeyFactoryAlgorithm);
        pbkdf2Strategy = new PBKDF2StrategyImpl(pbkdf2Properties);
    }

    @AfterEach
    void verifyMock() {
        verify(pbkdf2Properties).secret();
        verify(pbkdf2Properties).iterations();
        verify(pbkdf2Properties).saltLength();
        verify(pbkdf2Properties).secretKeyFactoryAlgorithm();
    }

    @Test
    void encrypt() {
        var response = pbkdf2Strategy.encrypt(rawPassword);

        assertThat(response).isNotNull()
                .extracting(EncryptionResponseDTO::passwordEncrypted)
                .matches(s -> s.length() == pbkdf2EncryptedPassword.length());
    }

    @Test
    void matches() {
        assertThatNoException()
                .isThrownBy(() -> {
                    var response = pbkdf2Strategy.matches(new PasswordMatchingRequestDTO(rawPassword, pbkdf2EncryptedPassword));
                    assertThat(response).isNotNull()
                            .extracting(PasswordMatchingResponseDTO::match)
                            .isEqualTo(true);
                });
    }

    @Test
    void DoesNotMatches() {
        assertThatNoException().isThrownBy(() -> {
            var response = pbkdf2Strategy.matches(new PasswordMatchingRequestDTO(wrongPassword, pbkdf2EncryptedPassword));
            assertThat(response).isNotNull()
                    .extracting(PasswordMatchingResponseDTO::match)
                    .isEqualTo(false);
        });
    }

}