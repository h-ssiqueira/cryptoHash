package com.hss.cryptohash.commons;

import com.hss.cryptohash.domain.Argon2StrategyImpl;
import com.hss.cryptohash.domain.BcryptStrategyImpl;
import com.hss.cryptohash.domain.PBKDF2StrategyImpl;
import com.hss.cryptohash.domain.ScryptStrategyImpl;
import com.hss.cryptohash.spec.CryptoHashStrategy;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum Algorithm {

    ARGON2(new Argon2StrategyImpl()),
    BCRYPT(new BcryptStrategyImpl()),
    SCRYPT(new ScryptStrategyImpl()),
    PBKDF2(new PBKDF2StrategyImpl());

    private final CryptoHashStrategy strategy;

}
