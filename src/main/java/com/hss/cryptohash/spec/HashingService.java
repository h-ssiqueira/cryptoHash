package com.hss.cryptohash.spec;


import com.hss.cryptohash.commons.HashConfig;
import com.hss.cryptohash.commons.PasswordMatchingDTO;

public interface HashingService {

    String encrypt(HashConfig configuration, String password);

    Boolean matches(PasswordMatchingDTO passwordMatchingDTO);
}
