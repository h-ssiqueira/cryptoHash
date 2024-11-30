package com.hss.cryptohash.commons.strategy;

import com.hss.cryptohash.spec.CryptoHashStrategy;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class Algorithm {

    private CryptoHashStrategy strategy;
}