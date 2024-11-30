package com.hss.cryptohash.commons.dto;

import java.io.Serializable;

public record ExceptionResponseDTO(String classType, String message) implements Serializable {
}
