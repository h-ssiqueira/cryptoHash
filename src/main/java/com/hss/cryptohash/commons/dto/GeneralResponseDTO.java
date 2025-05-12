package com.hss.cryptohash.commons.dto;

import io.quarkus.runtime.annotations.RegisterForReflection;

@RegisterForReflection
public record GeneralResponseDTO<T>(T data) {

}