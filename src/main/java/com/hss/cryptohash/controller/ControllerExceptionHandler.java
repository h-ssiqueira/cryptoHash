package com.hss.cryptohash.controller;

import com.hss.cryptohash.commons.CryptoHashException;
import com.hss.cryptohash.commons.dto.ExceptionResponseDTO;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

import static jakarta.ws.rs.core.Response.Status.BAD_REQUEST;

@Provider
public class ControllerExceptionHandler implements ExceptionMapper<CryptoHashException> {

    @Override
    public Response toResponse(CryptoHashException ex) {
        return Response.status(BAD_REQUEST).entity(new ExceptionResponseDTO(ex.getClazz(), ex.getMessage())).build();
    }
}
