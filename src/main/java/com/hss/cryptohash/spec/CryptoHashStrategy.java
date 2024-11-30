package com.hss.cryptohash.spec;


import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;

public interface CryptoHashStrategy {

    EncryptionResponseDTO encrypt(String password);

    void matches(PasswordMatchingRequestDTO passwordMatchingRequestDTO);
}