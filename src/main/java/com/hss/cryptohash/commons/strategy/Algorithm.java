package com.hss.cryptohash.commons.strategy;

import com.hss.cryptohash.spec.CryptoHashStrategy;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class Algorithm {

    private CryptoHashStrategy strategy;

    public enum AlgorithmStrategyEnum {
        ARGON2,
        BCRYPT,
        SCRYPT,
        PBKDF2,
        MD2,
        MD4,
        MD5,
        SHA1,
        SHA256,
        SHA3_224,
        SHA3_256,
        SHA3_384,
        SHA3_512,
        SHA384,
        SHA512_224,
        SHA512_256,
        SHA512,
        SHAKE,
        SKEIN,
        SM3,
        SPARKLE,
        TIGER,
        WHIRLPOOL,
        XOODYAK,
        BLAKE2B,
        BLAKE2BP,
        BLAKE2S,
        BLAKE2SP,
        BLAKE2XS,
        BLAKE3,
        GOST3411,
        GOST3411_2012_256,
        GOST3411_2012_512,
        RIPEMD128,
        RIPEMD160,
        RIPEMD256,
        RIPEMD320,
        CSHAKE,
        ASCON,
        DSTU7564,
        ISAP,
        KECCAK,
        PHOTONBEETLE;
    }
}