package com.hss.cryptohash.unit.domain.secure;

import com.hss.cryptohash.commons.config.ConfigApplicationProperties;
import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingResponseDTO;
import com.hss.cryptohash.domain.secure.ScryptStrategyImpl;
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
class ScryptStrategyImplTest extends CommonsTestConstants {

    @Mock
    private ConfigApplicationProperties.SCryptProperties scryptProperties;

    private ScryptStrategyImpl scryptStrategy;

    @BeforeEach
    void initMock() {
        when(scryptProperties.parallelization()).thenReturn(scryptParallelization);
        when(scryptProperties.cpuCost()).thenReturn(scryptCpuCost);
        when(scryptProperties.memoryCost()).thenReturn(scryptMemoryCost);
        when(scryptProperties.saltLength()).thenReturn(scryptSaltLength);
        when(scryptProperties.keyLength()).thenReturn(scryptKeyLength);
        scryptStrategy = new ScryptStrategyImpl(scryptProperties);
    }

    @AfterEach
    void verifyMock() {
        verify(scryptProperties).parallelization();
        verify(scryptProperties).cpuCost();
        verify(scryptProperties).memoryCost();
        verify(scryptProperties).saltLength();
        verify(scryptProperties).keyLength();
    }

    @Test
    void encrypt() {
        var response = scryptStrategy.encrypt(rawPassword);

        assertThat(response).isNotNull()
                .extracting(EncryptionResponseDTO::passwordEncrypted)
                .matches(s -> s.startsWith("$a1001$"));
    }

    @Test
    void matches() {
        assertThatNoException()
                .isThrownBy(() -> {
                    var response = scryptStrategy.matches(new PasswordMatchingRequestDTO(rawPassword, scryptEncryptedPassword));
                    assertThat(response).isNotNull()
                            .extracting(PasswordMatchingResponseDTO::match)
                            .isEqualTo(true);
                });
    }

    @Test
    void DoesNotMatches() {
        assertThatNoException().isThrownBy(() -> {
            var response = scryptStrategy.matches(new PasswordMatchingRequestDTO(wrongPassword, scryptEncryptedPassword));
            assertThat(response).isNotNull()
                    .extracting(PasswordMatchingResponseDTO::match)
                    .isEqualTo(false);
        });
    }

}