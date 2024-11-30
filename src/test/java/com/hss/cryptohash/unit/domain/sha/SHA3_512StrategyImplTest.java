package com.hss.cryptohash.unit.domain.sha;

import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.exception.CryptoHashException;
import com.hss.cryptohash.domain.sha.SHA3_512StrategyImpl;
import com.hss.cryptohash.unit.CommonsTestConstants;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SHA3_512StrategyImplTest extends CommonsTestConstants {

    private final SHA3_512StrategyImpl sha3_512Strategy = new SHA3_512StrategyImpl();

    @Test
    void encrypt() {
        var response = sha3_512Strategy.encrypt(rawPassword);

        assertThat(response).isNotNull()
                .extracting(EncryptionResponseDTO::passwordEncrypted)
                .isEqualTo(sha3_512EncryptedPassword);
    }

    @Test
    void matches() {
        assertThatNoException().isThrownBy(() -> sha3_512Strategy.matches(new PasswordMatchingRequestDTO(rawPassword, sha3_512EncryptedPassword)));
    }

    @Test
    void DoesNotMatches() {
        var request = new PasswordMatchingRequestDTO(wrongPassword, sha3_512EncryptedPassword);
        assertThatThrownBy(() -> sha3_512Strategy.matches(request))
                .isInstanceOf(CryptoHashException.class)
                .hasMessage("Invalid password!");
    }

}