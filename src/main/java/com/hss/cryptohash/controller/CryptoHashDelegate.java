package com.hss.cryptohash.controller;

import com.hss.cryptohash.commons.config.ConfigApplicationProperties;
import com.hss.cryptohash.commons.dto.EncryptionRequestDTO;
import com.hss.cryptohash.commons.dto.EncryptionResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingResponseDTO;
import com.hss.cryptohash.commons.strategy.Algorithm;
import com.hss.cryptohash.commons.strategy.AlgorithmStrategyEnum;
import com.hss.cryptohash.domain.AsconStrategyImpl;
import com.hss.cryptohash.domain.DSTU7564StrategyImpl;
import com.hss.cryptohash.domain.ISAPStrategyImpl;
import com.hss.cryptohash.domain.KeccakStrategyImpl;
import com.hss.cryptohash.domain.PhotonBeetleStrategyImpl;
import com.hss.cryptohash.domain.SM3StrategyImpl;
import com.hss.cryptohash.domain.SkeinStrategyImpl;
import com.hss.cryptohash.domain.SparkleStrategyImpl;
import com.hss.cryptohash.domain.TigerStrategyImpl;
import com.hss.cryptohash.domain.WhirlpoolStrategyImpl;
import com.hss.cryptohash.domain.XoodyakStrategyImpl;
import com.hss.cryptohash.domain.blake.Blake2bStrategyImpl;
import com.hss.cryptohash.domain.blake.Blake2bpStrategyImpl;
import com.hss.cryptohash.domain.blake.Blake2sStrategyImpl;
import com.hss.cryptohash.domain.blake.Blake2spStrategyImpl;
import com.hss.cryptohash.domain.blake.Blake2xsStrategyImpl;
import com.hss.cryptohash.domain.blake.Blake3StrategyImpl;
import com.hss.cryptohash.domain.gost3411.GOST3411StrategyImpl;
import com.hss.cryptohash.domain.gost3411.GOST3411_2012_256StrategyImpl;
import com.hss.cryptohash.domain.gost3411.GOST3411_2012_512StrategyImpl;
import com.hss.cryptohash.domain.md.MD2StrategyImpl;
import com.hss.cryptohash.domain.md.MD4StrategyImpl;
import com.hss.cryptohash.domain.md.MD5StrategyImpl;
import com.hss.cryptohash.domain.ripemd.RIPEMD128StrategyImpl;
import com.hss.cryptohash.domain.ripemd.RIPEMD160StrategyImpl;
import com.hss.cryptohash.domain.ripemd.RIPEMD256StrategyImpl;
import com.hss.cryptohash.domain.ripemd.RIPEMD320StrategyImpl;
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
import com.hss.cryptohash.domain.shake.CSHAKEStrategyImpl;
import com.hss.cryptohash.domain.shake.SHAKEStrategyImpl;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

@Singleton
public class CryptoHashDelegate {

    private final ConfigApplicationProperties properties;

    private final Algorithm strategy;

    @Inject
    public CryptoHashDelegate(ConfigApplicationProperties properties) {
        this.properties = properties;
        this.strategy = new Algorithm();
    }

    public void setStrategy(String strategy) {
        this.strategy.setStrategy(
            switch (AlgorithmStrategyEnum.valueOf(strategy)) {
                case ARGON2 -> new Argon2StrategyImpl(properties.argon2());
                case BCRYPT -> new BcryptStrategyImpl(properties.bcrypt());
                case SCRYPT -> new ScryptStrategyImpl(properties.scrypt());
                case PBKDF2 -> new PBKDF2StrategyImpl(properties.pbkdf2());
                case MD2 -> new MD2StrategyImpl();
                case MD4 -> new MD4StrategyImpl();
                case MD5 -> new MD5StrategyImpl();
                case SHA1 -> new SHA1StrategyImpl();
                case SHA256 -> new SHA256StrategyImpl();
                case SHA3_224 -> new SHA3_224StrategyImpl();
                case SHA3_256 -> new SHA3_256StrategyImpl();
                case SHA3_512 -> new SHA3_512StrategyImpl();
                case SHA3_384 -> new SHA3_384StrategyImpl();
                case SHA384 -> new SHA384StrategyImpl();
                case SHA512_224 -> new SHA512_224StrategyImpl();
                case SHA512_256 -> new SHA512_256StrategyImpl();
                case SHA512 -> new SHA512StrategyImpl();
                case SHAKE -> new SHAKEStrategyImpl();
                case SKEIN -> new SkeinStrategyImpl(properties.skein());
                case SM3 -> new SM3StrategyImpl();
                case SPARKLE -> new SparkleStrategyImpl(properties.sparkle());
                case TIGER -> new TigerStrategyImpl();
                case WHIRLPOOL -> new WhirlpoolStrategyImpl();
                case XOODYAK -> new XoodyakStrategyImpl();
                case BLAKE3 -> new Blake3StrategyImpl(properties.blake3());
                case BLAKE2B -> new Blake2bStrategyImpl();
                case BLAKE2BP -> new Blake2bpStrategyImpl(properties.blake2bp());
                case BLAKE2S -> new Blake2sStrategyImpl();
                case BLAKE2SP -> new Blake2spStrategyImpl(properties.blake2sp());
                case BLAKE2XS -> new Blake2xsStrategyImpl();
                case ISAP -> new ISAPStrategyImpl();
                case ASCON -> new AsconStrategyImpl(properties.ascon());
                case CSHAKE -> new CSHAKEStrategyImpl(properties.cshake());
                case KECCAK -> new KeccakStrategyImpl();
                case DSTU7564 -> new DSTU7564StrategyImpl(properties.dstu7564());
                case PHOTONBEETLE -> new PhotonBeetleStrategyImpl();
                case GOST3411 -> new GOST3411StrategyImpl();
                case GOST3411_2012_256 -> new GOST3411_2012_256StrategyImpl();
                case GOST3411_2012_512 -> new GOST3411_2012_512StrategyImpl();
                case RIPEMD128 -> new RIPEMD128StrategyImpl();
                case RIPEMD160 -> new RIPEMD160StrategyImpl();
                case RIPEMD256 -> new RIPEMD256StrategyImpl();
                case RIPEMD320 -> new RIPEMD320StrategyImpl();
        });
    }

    public PasswordMatchingResponseDTO match(PasswordMatchingRequestDTO dto) {
        return this.strategy.getStrategy().matches(dto);
    }

    public EncryptionResponseDTO encrypt(EncryptionRequestDTO dto) {
        return this.strategy.getStrategy().encrypt(dto.password());
    }
}