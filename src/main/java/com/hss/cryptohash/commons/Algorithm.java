package com.hss.cryptohash.commons;

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

    ARGON2(new Argon2StrategyImpl()),
    BCRYPT(new BcryptStrategyImpl()),
    SCRYPT(new ScryptStrategyImpl()),
    PBKDF2(new PBKDF2StrategyImpl()),
    MD2(new MD2StrategyImpl()),
    MD5(new MD5StrategyImpl()),
    SHA_1(new SHA1StrategyImpl()),
    SHA_256(new SHA256StrategyImpl()),
    SHA3_224(new SHA3_224StrategyImpl()),
    SHA3_256(new SHA3_256StrategyImpl()),
    SHA3_384(new SHA3_384StrategyImpl()),
    SHA3_512(new SHA3_512StrategyImpl()),
    SHA_384(new SHA384StrategyImpl()),
    SHA_512_224(new SHA512_224StrategyImpl()),
    SHA_512_256(new SHA512_256StrategyImpl()),
    SHA_512(new SHA512StrategyImpl()),

    ;

    private final CryptoHashStrategy strategy;

}
