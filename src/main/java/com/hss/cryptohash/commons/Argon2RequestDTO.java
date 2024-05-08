package com.hss.cryptohash.commons;

public record Argon2RequestDTO(String password, Integer saltLength, Integer keyLength) {
}
