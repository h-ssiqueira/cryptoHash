package com.hss.cryptohash.commons;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class HashConfig {

    private Integer saltLength;
    private Integer keyLength;
    private Integer strength;
}
