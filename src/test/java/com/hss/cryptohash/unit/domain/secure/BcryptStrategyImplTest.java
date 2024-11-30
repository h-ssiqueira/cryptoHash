package com.hss.cryptohash.unit.domain.secure;

import com.hss.cryptohash.commons.config.ConfigApplicationProperties;
import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.exception.CryptoHashException;
import com.hss.cryptohash.domain.secure.BcryptStrategyImpl;
import com.hss.cryptohash.unit.CommonsTestConstants;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class BcryptStrategyImplTest extends CommonsTestConstants {

    @Mock
    private ConfigApplicationProperties.BCryptProperties bcryptProperties;

    private BcryptStrategyImpl bcryptStrategy;

    @BeforeEach
    void initMock() {
        when(bcryptProperties.strength()).thenReturn(bcryptStrength);
        bcryptStrategy = new BcryptStrategyImpl(bcryptProperties);
    }

    @AfterEach
    void verifyMock() {
        verify(bcryptProperties).strength();
    }

    @Test
    void encrypt() {
        var response = bcryptStrategy.encrypt(rawPassword);

        assertThat(response).isNotNull()
                .extracting(EncryptionResponseDTO::passwordEncrypted)
                .matches(s -> s.startsWith("$2a$10$"));
    }

    @Test
    void matches() {
        assertThatNoException().isThrownBy(() -> bcryptStrategy.matches(new PasswordMatchingRequestDTO(rawPassword, bCryptEncryptedPassword)));
    }

    @Test
    void DoesNotMatches() {
        var request = new PasswordMatchingRequestDTO(wrongPassword, bCryptEncryptedPassword);
        assertThatThrownBy(() -> bcryptStrategy.matches(request))
                .isInstanceOf(CryptoHashException.class)
                .hasMessage("Invalid password!");
    }

}