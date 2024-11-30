package com.hss.cryptohash.unit.domain.md;

import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.exception.CryptoHashException;
import com.hss.cryptohash.domain.md.MD2StrategyImpl;
import com.hss.cryptohash.unit.CommonsTestConstants;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MD2StrategyImplTest extends CommonsTestConstants {

    private final MD2StrategyImpl md2Strategy = new MD2StrategyImpl();

    @Test
    void encrypt() {
        var response = md2Strategy.encrypt(rawPassword);

        assertThat(response).isNotNull()
                .extracting(EncryptionResponseDTO::passwordEncrypted)
                .isEqualTo(md2EncryptedPassword);
    }

    @Test
    void matches() {
        assertThatNoException().isThrownBy(() -> md2Strategy.matches(new PasswordMatchingRequestDTO(rawPassword, md2EncryptedPassword)));
    }

    @Test
    void DoesNotMatches() {
        var request = new PasswordMatchingRequestDTO(wrongPassword, md2EncryptedPassword);
        assertThatThrownBy(() -> md2Strategy.matches(request))
                .isInstanceOf(CryptoHashException.class)
                .hasMessage("Invalid password!");
    }
}