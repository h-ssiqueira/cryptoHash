package com.hss.cryptohash.commons.config;

import io.smallrye.config.ConfigMapping;

@ConfigMapping(prefix = "hash")
public interface ConfigApplicationProperties {

    SparkleProperties sparkle();
    SkeinProperties skein();
    Blake2bpProperties blake2bp();
    Blake2spProperties blake2sp();
    Blake3Properties blake3();
    PBKDF2Properties pbkdf2();
    SCryptProperties scrypt();
    Argon2Properties argon2();
    BCryptProperties bcrypt();

    interface SparkleProperties {
        String param();
    }

    interface SkeinProperties {
        int outputSize();
        int blockSize();
    }

    interface Blake2bpProperties {
        String key();
    }

    interface Blake2spProperties {
        String key();
    }

    interface Blake3Properties {
        String key();
    }

    interface PBKDF2Properties {
        String secret();
        int saltLength();
        int iterations();
        String secretKeyFactoryAlgorithm();
    }

    interface SCryptProperties {
        int cpuCost();
        int memoryCost();
        int parallelization();
        int keyLength();
        int saltLength();
    }

    interface Argon2Properties {
        int saltLength();
        int hashLength();
        int parallelism();
        int memory();
        int iterations();
    }

    interface BCryptProperties {
        int strength();
    }
}