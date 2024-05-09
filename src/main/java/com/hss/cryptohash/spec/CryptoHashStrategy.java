package com.hss.cryptohash.spec;


import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.MatchedResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingDTO;

public interface CryptoHashStrategy {

    EncryptionResponseDTO encrypt(String password);

    MatchedResponseDTO matches(PasswordMatchingDTO passwordMatchingDTO);
}