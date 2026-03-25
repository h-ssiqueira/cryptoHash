package com.hss.cryptohash.commons.dto;

import io.quarkus.runtime.annotations.RegisterForReflection;

import java.io.Serializable;
import java.util.List;

@SuppressWarnings("unused")
@RegisterForReflection
public record AlgorithmListResponseDTO(List<String> algorithms) implements Serializable {
}