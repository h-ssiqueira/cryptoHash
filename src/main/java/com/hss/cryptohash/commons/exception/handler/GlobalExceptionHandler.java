package com.hss.cryptohash.commons.exception.handler;

import com.hss.cryptohash.commons.dto.ExceptionResponseDTO;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import lombok.extern.slf4j.Slf4j;

import static jakarta.ws.rs.core.Response.Status.BAD_REQUEST;

@Provider
@Slf4j
public class GlobalExceptionHandler implements ExceptionMapper<Exception> {
    @Override
    public Response toResponse(Exception ex) {
        log.error(ex.toString());
        return Response.status(BAD_REQUEST).entity(new ExceptionResponseDTO(ex.getClass().toString(), ex.getMessage())).build();
    }
}