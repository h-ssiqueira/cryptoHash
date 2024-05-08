package com.hss.cryptohash.domain;

import com.hss.cryptohash.commons.HashConfig;
import com.hss.cryptohash.commons.PasswordMatchingDTO;
import com.hss.cryptohash.spec.HashingService;
import jakarta.enterprise.context.ApplicationScoped;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@ApplicationScoped
public class BcryptServiceImpl implements HashingService {

    @Override
    public String encrypt(HashConfig configuration, String password) {
        return new BCryptPasswordEncoder(configuration.getStrength()).encode(password);
    }

    @Override
    public Boolean matches(PasswordMatchingDTO passwordMatchingDTO) {
        return new BCryptPasswordEncoder().matches(passwordMatchingDTO.rawPassword(), passwordMatchingDTO.encryptedPassword());
    }
}
