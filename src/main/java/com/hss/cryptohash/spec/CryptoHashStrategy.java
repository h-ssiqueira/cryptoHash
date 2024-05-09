package com.hss.cryptohash.spec;


import com.hss.cryptohash.commons.EncryptionResponseDTO;
import com.hss.cryptohash.commons.MatchedResponseDTO;
import com.hss.cryptohash.commons.PasswordMatchingDTO;

public interface CryptoHashStrategy {

    EncryptionResponseDTO encrypt(String password);

    MatchedResponseDTO matches(PasswordMatchingDTO passwordMatchingDTO);
}
