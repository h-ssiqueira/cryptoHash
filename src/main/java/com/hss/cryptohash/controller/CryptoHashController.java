package com.hss.cryptohash.controller;

import com.hss.cryptohash.commons.EncryptionRequestDTO;
import com.hss.cryptohash.commons.PasswordMatchingDTO;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.validation.Valid;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import lombok.extern.slf4j.Slf4j;

import static jakarta.ws.rs.core.MediaType.APPLICATION_JSON;

@Slf4j
@Singleton
@Path("/api/v1")
public class CryptoHashController {

    private final CryptoHashDelegate cryptoHashDelegate;

    @Inject
    public CryptoHashController(CryptoHashDelegate cryptoHashDelegate) {
        this.cryptoHashDelegate = cryptoHashDelegate;
    }

    @POST
    @Path("/encrypt")
    @Produces(APPLICATION_JSON)
    @Consumes(APPLICATION_JSON)
    public Response encrypt(@Valid EncryptionRequestDTO encryptionRequestDTO, @Context HttpHeaders headers) {
        var header = extractStrategy(headers);
        log.debug("{} encryption", header);
        cryptoHashDelegate.setStrategy(header);
        return Response.ok().entity(cryptoHashDelegate.encrypt(encryptionRequestDTO)).build();
    }

    @POST
    @Path("/match")
    @Produces(APPLICATION_JSON)
    @Consumes(APPLICATION_JSON)
    public Response match(@Valid PasswordMatchingDTO passwordMatchingDTO, @Context HttpHeaders headers) {
        var header = extractStrategy(headers);
        log.debug("{} match", header);
        cryptoHashDelegate.setStrategy(header);
        return Response.ok().entity(cryptoHashDelegate.match(passwordMatchingDTO)).build();
    }

    private String extractStrategy(HttpHeaders headers) {
        return headers.getRequestHeaders().get("cryptoHashStrategy").get(0);
    }
}
