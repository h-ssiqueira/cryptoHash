package com.hss.cryptohash.commons.exception.handler;

import com.hss.cryptohash.commons.dto.ExceptionResponseDTO;
import com.hss.cryptohash.commons.exception.CryptoHashException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import lombok.extern.slf4j.Slf4j;

import java.util.Arrays;

import static jakarta.ws.rs.core.Response.Status.BAD_REQUEST;

@Provider
@Slf4j
public class CryptoHashExceptionHandler implements ExceptionMapper<CryptoHashException> {

    @Override
    public Response toResponse(CryptoHashException ex) {
        log.error(Arrays.toString(ex.getStackTrace()));
        return Response.status(BAD_REQUEST).entity(new ExceptionResponseDTO(ex.getClazz(), ex.getMessage())).build();
    }
}