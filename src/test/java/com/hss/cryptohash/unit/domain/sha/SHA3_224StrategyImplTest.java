package com.hss.cryptohash.unit.domain.sha;

import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.exception.CryptoHashException;
import com.hss.cryptohash.domain.sha.SHA3_224StrategyImpl;
import com.hss.cryptohash.unit.CommonsTestConstants;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SHA3_224StrategyImplTest extends CommonsTestConstants {

    private final SHA3_224StrategyImpl sha3_224Strategy = new SHA3_224StrategyImpl();

    @Test
    void encrypt() {
        var response = sha3_224Strategy.encrypt(rawPassword);

        assertThat(response).isNotNull()
                .extracting(EncryptionResponseDTO::passwordEncrypted)
                .isEqualTo(sha3_224EncryptedPassword);
    }

    @Test
    void matches() {
        assertThatNoException().isThrownBy(() -> sha3_224Strategy.matches(new PasswordMatchingRequestDTO(rawPassword, sha3_224EncryptedPassword)));
    }

    @Test
    void DoesNotMatches() {
        var request = new PasswordMatchingRequestDTO(wrongPassword, sha3_224EncryptedPassword);
        assertThatThrownBy(() -> sha3_224Strategy.matches(request))
                .isInstanceOf(CryptoHashException.class)
                .hasMessage("Invalid password!");
    }

}