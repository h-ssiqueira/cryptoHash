package com.hss.cryptohash.unit;

import java.nio.file.Paths;

import static java.nio.file.Files.readString;

public abstract class CommonsTestConstants {

    protected static final String rawPassword = "admin";
    protected static final String wrongPassword = "it's the Wrong pass";

    // MD
    protected static final String md2EncryptedPassword = "3e3e6b0e5c1c68644fc5ce3cf060211d";
    protected static final String md4EncryptedPassword = "f9d4049dd6a4dc35d40e5265954b2a46";
    protected static final String md5EncryptedPassword = "21232f297a57a5a743894a0e4a801fc3";

    // Secure
    protected static final String argon2EncryptedPassword = "$argon2id$v=19$m=1024,t=9,p=1$u1yod6w/Sl2RLbHA8XQLf5iB/n+fTq9yTVCwbp3E490xzlGuMpVrDYHW2XwXK8gM9YWaOmMm19F2SLTK95FQxg$zF15nr8EZnByiPOcHj9SpiGTJ+448sP+ylaL1kGYsH/o59sunfH7pvxGdE2s59iw+uxviUUohrwXXI45qV0DjdZC58DyVOENse0p3/Iq7+wGCBgESpP/PmbyqP+C5SvfhWb7uCJNjtyQzXb+zPgv7BoPoMA5pENPrCG7AfXcziw";
    protected static final int argon2Parallelism = 1;
    protected static final int argon2Iterations = 9;
    protected static final int argon2Memory = 1024;
    protected static final int argon2SaltLength = 64;
    protected static final int argon2HashLength = 128;
    protected static final String bCryptEncryptedPassword = "$2a$10$yrCx167lGkkf.A/PprSJdeqpzl5K6V4q8qzcNUMezUBWHTTQ0tiJ.";
    protected static final int bcryptStrength = 10;
    protected static final String pbkdf2EncryptedPassword = "f2cd5f9251a88b6dc2140203aa603583ee8e4fcd0a3691c0da0dd190dde1f1b3067e6340eab6f2e64e86a1a90c847b4d3aa6ee135c611f8976d5bfe1b928ac187b74468028dbbab38e6a1270a4ac9b47056bf3ff7241b5f391a5fbf8a93af3045291275ffa2b424e3f0fdd6afbdc994fcb6a6a8db415d3067cf48caddc5cdfef";
    protected static final int pbkdf2Iterations = 10;
    protected static final String pbkdf2Secret = "randomSecret";
    protected static final int pbkdf2SaltLength = 64;
    protected static final String pbkdf2SecretKeyFactoryAlgorithm = "PBKDF2WithHmacSHA512";
    protected static final String scryptEncryptedPassword = "$a1001$BdvV64ZKUVFf6ePA3yVKjjbv4wX0aUrSkDVuOKFXRk3zICz8sRKo5bL7NqQc3VRTOi3ZPTMfK5Zx3H/GYRJRDA==$pwK4ZGeW8cUZ0kL7+tZBJnC90LoZ17IXpOt53+FMdclIXaWSTRyk3ZibWs6jeZuYZ09HlX3gKNIvdJDwhEhd86QzYz1x+DSAhTKJXBgKvxpiIkL0Z/ZZctxXHGNkFV8zQojMGzdHhsBpYjGmPamX0e/hecrE80NuAt5Xvdp5bdM=";

    protected static final int scryptParallelization = 1;
    protected static final int scryptCpuCost = 1024;
    protected static final int scryptMemoryCost = 16;
    protected static final int scryptSaltLength = 64;
    protected static final int scryptKeyLength = 128;

    // SHA
    protected static final String sha1EncryptedPassword = "d033e22ae348aeb5660fc2140aec35850c4da997";
    protected static final String sha3_224EncryptedPassword = "a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20";
    protected static final String sha3_256EncryptedPassword = "fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b";
    protected static final String sha3_384EncryptedPassword = "9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3";
    protected static final String sha3_512EncryptedPassword = "5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d";
    protected static final String sha256EncryptedPassword = "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918";
    protected static final String sha384EncryptedPassword = "9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782";
    protected static final String sha512_224EncryptedPassword = "9500df153ab6b96cdd6bf301e6062564009ebfff9c14aa1405d26be3";
    protected static final String sha512_256EncryptedPassword = "30bb8411dd0cbf96b10a52371f7b3be1690f7afa16c3bd7bc7d02c0e2854768d";
    protected static final String sha512EncryptedPassword = "c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec";

    // Blake
    protected static final String blake2bEncryptedPassword = "bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11";
    protected static final String blake2bpEncryptedPassword = "99cbadccd352e7caff9c097213424cbd9b45d973ed849ed17a1b3f9701c0e180cd321b77c782694e1c2e1d95ba3b2be95e9175d1759e429c48c63060811dcbdd";
    protected static final String blake2bpKey = "superSecretHashKeyWLength32bytes";
    protected static final String blake2sEncryptedPassword = "327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124";
    protected static final String blake2spEncryptedPassword = "18e892e23a2199162ca366ea5865b979df45e9bfc30685194271625456578a3a";
    protected static final String blake2spKey = "superSecretHashKeyWLength32bytes";
    protected static final String blake2xsEncryptedPassword;

    static {
        String content = "";
        try {
            content = readString(Paths.get(CommonsTestConstants.class.getClassLoader().getResource("blake2xsEncryptedPassword.txt").toURI()));
        } catch (Exception ignored) {}
        blake2xsEncryptedPassword = content;
    }

    protected static final String blake3EncryptedPassword = "27c31968eee615f9fff64f07b1cec9ed6d18435b21131130415937ddb7f14d0a";
    protected static final String blake3Key = "superSecretHashKeyWLength32bytes";

    protected static final String shakeEncryptedPassword = "4a99ec385482c871a1a823044b7e71c7d35652f4ba7653f91f6aafabe4bdfb32";
    protected static final String skeinEncryptedPassword = "e3e3c32a62e8a850fc91f97754baea54";
    protected static final int skeinOutputSize = 128;
    protected static final int skeinBlockSize = 512;
    protected static final String sm3EncryptedPassword = "dc1fd00e3eeeb940ff46f457bf97d66ba7fcc36e0b20802383de142860e76ae6";
    protected static final String sparkleEncryptedPassword = "93bf5c836e0c785d4ca8ca708f670e81c0aa8415ace49ecb1533b4a1424189715f0e76ee496d714e0e716fe81ecf22f5";
    protected static final String sparkleParam = "ESCH384";
    protected static final String tigerEncryptedPassword = "a2614727bca6549236c470392e1e122ac135083b1ecb30ac";
    protected static final String whirlpoolEncryptedPassword = "6a4e012bd9583858a5a6fa15f58bd86a25af266d3a4344f1ec2018b778f29ba83be86eb45e6dc204e11276f4a99eff4e2144fbe15e756c2c88e999649aae7d94";
    protected static final String xoodyakEncryptedPassword = "caf55000e1713930afe1839ed43f43908eec746e73b2f43644b776d193492d5a";

}