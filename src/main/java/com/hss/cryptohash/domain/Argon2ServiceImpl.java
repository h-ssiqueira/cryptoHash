package com.hss.cryptohash.domain;

import com.hss.cryptohash.commons.HashConfig;
import com.hss.cryptohash.commons.PasswordMatchingDTO;
import com.hss.cryptohash.spec.HashingService;
import jakarta.enterprise.context.ApplicationScoped;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

@ApplicationScoped
public class Argon2ServiceImpl implements HashingService {

    @Override
    public String encrypt(HashConfig configuration, String password) {
        return new Argon2PasswordEncoder(configuration.getSaltLength(), configuration.getKeyLength(), 1,1024,10).encode(password);
    }

    @Override
    public Boolean matches(PasswordMatchingDTO passwordMatchingDTO) {
        return new Argon2PasswordEncoder(1,2,1,1024,5).matches(passwordMatchingDTO.rawPassword(), passwordMatchingDTO.encryptedPassword());
    }
}
