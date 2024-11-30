package com.hss.cryptohash.unit.domain.sha;

import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.exception.CryptoHashException;
import com.hss.cryptohash.domain.sha.SHA384StrategyImpl;
import com.hss.cryptohash.unit.CommonsTestConstants;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SHA384StrategyImplTest extends CommonsTestConstants {

    private final SHA384StrategyImpl sha384Strategy = new SHA384StrategyImpl();

    @Test
    void encrypt() {
        var response = sha384Strategy.encrypt(rawPassword);

        assertThat(response).isNotNull()
                .extracting(EncryptionResponseDTO::passwordEncrypted)
                .isEqualTo(sha384EncryptedPassword);
    }

    @Test
    void matches() {
        assertThatNoException().isThrownBy(() -> sha384Strategy.matches(new PasswordMatchingRequestDTO(rawPassword, sha384EncryptedPassword)));
    }

    @Test
    void DoesNotMatches() {
        var request = new PasswordMatchingRequestDTO(wrongPassword, sha384EncryptedPassword);
        assertThatThrownBy(() -> sha384Strategy.matches(request))
                .isInstanceOf(CryptoHashException.class)
                .hasMessage("Invalid password!");
    }

}