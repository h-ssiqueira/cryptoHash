package com.hss.cryptohash.spec;


import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingResponseDTO;

public interface CryptoHashStrategy {

    EncryptionResponseDTO encrypt(String password);

    PasswordMatchingResponseDTO matches(PasswordMatchingRequestDTO passwordMatchingRequestDTO);
}