package com.hss.cryptohash.commons;

import com.hss.cryptohash.domain.Blake3StrategyImpl;
import com.hss.cryptohash.domain.md5.MD2StrategyImpl;
import com.hss.cryptohash.domain.md5.MD5StrategyImpl;
import com.hss.cryptohash.domain.secure.Argon2StrategyImpl;
import com.hss.cryptohash.domain.secure.BcryptStrategyImpl;
import com.hss.cryptohash.domain.secure.PBKDF2StrategyImpl;
import com.hss.cryptohash.domain.secure.ScryptStrategyImpl;
import com.hss.cryptohash.domain.sha.SHA1StrategyImpl;
import com.hss.cryptohash.domain.sha.SHA256StrategyImpl;
import com.hss.cryptohash.domain.sha.SHA384StrategyImpl;
import com.hss.cryptohash.domain.sha.SHA3_224StrategyImpl;
import com.hss.cryptohash.domain.sha.SHA3_256StrategyImpl;
import com.hss.cryptohash.domain.sha.SHA3_384StrategyImpl;
import com.hss.cryptohash.domain.sha.SHA3_512StrategyImpl;
import com.hss.cryptohash.domain.sha.SHA512StrategyImpl;
import com.hss.cryptohash.domain.sha.SHA512_224StrategyImpl;
import com.hss.cryptohash.domain.sha.SHA512_256StrategyImpl;
import com.hss.cryptohash.spec.CryptoHashStrategy;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum Algorithm {

    ARGON2("ARGON2", new Argon2StrategyImpl()),
    BCRYPT("BCRYPT", new BcryptStrategyImpl()),
    SCRYPT("SCRYPT", new ScryptStrategyImpl()),
    PBKDF2("PBKDF2", new PBKDF2StrategyImpl()),
    MD2("MD2", new MD2StrategyImpl()),
    MD5("MD5", new MD5StrategyImpl()),
    SHA1("SHA1", new SHA1StrategyImpl()),
    SHA256("SHA256", new SHA256StrategyImpl()),
    SHA3_224("SHA3_224", new SHA3_224StrategyImpl()),
    SHA3_256("SHA3_256", new SHA3_256StrategyImpl()),
    SHA3_384("SHA3_384", new SHA3_384StrategyImpl()),
    SHA3_512("SHA3_512", new SHA3_512StrategyImpl()),
    SHA384("SHA384", new SHA384StrategyImpl()),
    SHA512_224("SHA512_224", new SHA512_224StrategyImpl()),
    SHA512_256("SHA512_256", new SHA512_256StrategyImpl()),
    SHA512("SHA512", new SHA512StrategyImpl()),
    BLAKE3("BLAKE3", new Blake3StrategyImpl());

    private final String value;

    private final CryptoHashStrategy strategy;

}
