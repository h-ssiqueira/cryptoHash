package com.hss.cryptohash.commons.dto;

import java.io.Serializable;
import java.util.List;

public record AlgorithmListResponseDTO(List<String> algorithms, Integer total) implements Serializable {
}
