package com.hss.cryptohash.unit.domain.secure;

import com.hss.cryptohash.commons.config.ConfigApplicationProperties;
import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.exception.CryptoHashException;
import com.hss.cryptohash.domain.secure.Argon2StrategyImpl;
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
class Argon2StrategyImplTest extends CommonsTestConstants {

    @Mock
    private ConfigApplicationProperties.Argon2Properties argon2Properties;

    private Argon2StrategyImpl argon2StrategyImpl;

    @BeforeEach
    void initMock() {
        when(argon2Properties.parallelism()).thenReturn(argon2Parallelism);
        when(argon2Properties.iterations()).thenReturn(argon2Iterations);
        when(argon2Properties.memory()).thenReturn(argon2Memory);
        when(argon2Properties.saltLength()).thenReturn(argon2SaltLength);
        when(argon2Properties.hashLength()).thenReturn(argon2HashLength);
        argon2StrategyImpl = new Argon2StrategyImpl(argon2Properties);
    }

    @AfterEach
    void verifyMock() {
        verify(argon2Properties).parallelism();
        verify(argon2Properties).iterations();
        verify(argon2Properties).memory();
        verify(argon2Properties).saltLength();
        verify(argon2Properties).hashLength();
    }

    @Test
    void encrypt() {
        var response = argon2StrategyImpl.encrypt(rawPassword);

        assertThat(response).isNotNull()
                .extracting(EncryptionResponseDTO::passwordEncrypted)
                .matches(s -> s.startsWith("$argon2id$v=19$m=1024,t=9,p=1$"));
    }

    @Test
    void matches() {
        assertThatNoException().isThrownBy(() -> argon2StrategyImpl.matches(new PasswordMatchingRequestDTO(rawPassword, argon2EncryptedPassword)));
    }

    @Test
    void DoesNotMatches() {
        var request = new PasswordMatchingRequestDTO(wrongPassword, argon2EncryptedPassword);
        assertThatThrownBy(() -> argon2StrategyImpl.matches(request))
                .isInstanceOf(CryptoHashException.class)
                .hasMessage("Invalid password!");
    }

}