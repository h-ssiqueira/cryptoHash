package com.hss.cryptohash.unit;

public abstract class CommonsTestConstants {

    protected String rawPassword = "admin";
    protected String wrongPassword = "it's the Wrong pass";

    // MD
    protected String md2EncryptedPassword = "3e3e6b0e5c1c68644fc5ce3cf060211d";
    protected String md5EncryptedPassword = "21232f297a57a5a743894a0e4a801fc3";

    // Secure
    protected String argon2EncryptedPassword = "$argon2id$v=19$m=1024,t=9,p=1$u1yod6w/Sl2RLbHA8XQLf5iB/n+fTq9yTVCwbp3E490xzlGuMpVrDYHW2XwXK8gM9YWaOmMm19F2SLTK95FQxg$zF15nr8EZnByiPOcHj9SpiGTJ+448sP+ylaL1kGYsH/o59sunfH7pvxGdE2s59iw+uxviUUohrwXXI45qV0DjdZC58DyVOENse0p3/Iq7+wGCBgESpP/PmbyqP+C5SvfhWb7uCJNjtyQzXb+zPgv7BoPoMA5pENPrCG7AfXcziw";
    protected int argon2Parallelism = 1;
    protected int argon2Iterations = 9;
    protected int argon2Memory = 1024;
    protected int argon2SaltLength = 64;
    protected int argon2HashLength = 128;
    protected String bCryptEncryptedPassword = "$2a$10$yrCx167lGkkf.A/PprSJdeqpzl5K6V4q8qzcNUMezUBWHTTQ0tiJ.";
    protected int bcryptStrength = 10;
    protected String pbkdf2EncryptedPassword = "f2cd5f9251a88b6dc2140203aa603583ee8e4fcd0a3691c0da0dd190dde1f1b3067e6340eab6f2e64e86a1a90c847b4d3aa6ee135c611f8976d5bfe1b928ac187b74468028dbbab38e6a1270a4ac9b47056bf3ff7241b5f391a5fbf8a93af3045291275ffa2b424e3f0fdd6afbdc994fcb6a6a8db415d3067cf48caddc5cdfef";
    protected int pbkdf2Iterations = 10;
    protected String pbkdf2Secret = "randomSecret";
    protected int pbkdf2SaltLength = 64;
    protected String pbkdf2SecretKeyFactoryAlgorithm = "PBKDF2WithHmacSHA512";
    protected String scryptEncryptedPassword = "$a1001$BdvV64ZKUVFf6ePA3yVKjjbv4wX0aUrSkDVuOKFXRk3zICz8sRKo5bL7NqQc3VRTOi3ZPTMfK5Zx3H/GYRJRDA==$pwK4ZGeW8cUZ0kL7+tZBJnC90LoZ17IXpOt53+FMdclIXaWSTRyk3ZibWs6jeZuYZ09HlX3gKNIvdJDwhEhd86QzYz1x+DSAhTKJXBgKvxpiIkL0Z/ZZctxXHGNkFV8zQojMGzdHhsBpYjGmPamX0e/hecrE80NuAt5Xvdp5bdM=";

    protected int scryptParallelization = 1;
    protected int scryptCpuCost = 1024;
    protected int scryptMemoryCost = 16;
    protected int scryptSaltLength = 64;
    protected int scryptKeyLength = 128;

    // SHA
    protected String sha1EncryptedPassword = "d033e22ae348aeb5660fc2140aec35850c4da997";
    protected String sha3_224EncryptedPassword = "a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20";
    protected String sha3_256EncryptedPassword = "fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b";
    protected String sha3_384EncryptedPassword = "9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3";
    protected String sha3_512EncryptedPassword = "5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d";
    protected String sha256EncryptedPassword = "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918";
    protected String sha384EncryptedPassword = "9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782";
    protected String sha512_224EncryptedPassword = "9500df153ab6b96cdd6bf301e6062564009ebfff9c14aa1405d26be3";
    protected String sha512_256EncryptedPassword = "30bb8411dd0cbf96b10a52371f7b3be1690f7afa16c3bd7bc7d02c0e2854768d";
    protected String sha512EncryptedPassword = "c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec";

    // Blake 3
    protected String blake3EncryptedPassword = "27c31968eee615f9fff64f07b1cec9ed6d18435b21131130415937ddb7f14d0a";
    protected String blake3Key = "superSecretHashKeyWLength32bytes";

}