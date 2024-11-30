package com.hss.cryptohash.unit.domain.sha;

import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.exception.CryptoHashException;
import com.hss.cryptohash.domain.sha.SHA512StrategyImpl;
import com.hss.cryptohash.unit.CommonsTestConstants;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SHA512StrategyImplTest extends CommonsTestConstants {

    private final SHA512StrategyImpl sha512Strategy = new SHA512StrategyImpl();

    @Test
    void encrypt() {
        var response = sha512Strategy.encrypt(rawPassword);

        assertThat(response).isNotNull()
                .extracting(EncryptionResponseDTO::passwordEncrypted)
                .isEqualTo(sha512EncryptedPassword);
    }

    @Test
    void matches() {
        assertThatNoException().isThrownBy(() -> sha512Strategy.matches(new PasswordMatchingRequestDTO(rawPassword, sha512EncryptedPassword)));
    }

    @Test
    void DoesNotMatches() {
        var request = new PasswordMatchingRequestDTO(wrongPassword, sha512EncryptedPassword);
        assertThatThrownBy(() -> sha512Strategy.matches(request))
                .isInstanceOf(CryptoHashException.class)
                .hasMessage("Invalid password!");
    }

}