package com.hss.cryptohash.controller;

import com.hss.cryptohash.commons.Argon2RequestDTO;
import com.hss.cryptohash.commons.HashConfig;
import com.hss.cryptohash.commons.PasswordMatchingDTO;
import com.hss.cryptohash.domain.Argon2ServiceImpl;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static jakarta.ws.rs.core.MediaType.APPLICATION_JSON;

@Path("/api/v1/argon2")
public class Argon2Controller {

    private static final Logger LOG = LoggerFactory.getLogger(Argon2Controller.class);

    private final Argon2ServiceImpl argon2ServiceImpl;

    @Inject
    public Argon2Controller(Argon2ServiceImpl argon2ServiceImpl) {
        this.argon2ServiceImpl = argon2ServiceImpl;
    }

    @POST
    @Path("/encrypt")
    @Produces(APPLICATION_JSON)
    @Consumes(APPLICATION_JSON)
    Response encrypt(Argon2RequestDTO argon2RequestDTO) {
        LOG.info("Argon2 encription");
        return Response.ok().entity(argon2ServiceImpl.encrypt(HashConfig.builder()
                .keyLength(argon2RequestDTO.keyLength())
                .saltLength(argon2RequestDTO.saltLength()).build(), argon2RequestDTO.password())).build();
    }

    @POST
    @Path("/match")
    @Produces(APPLICATION_JSON)
    @Consumes(APPLICATION_JSON)
    Response match(PasswordMatchingDTO passwordMatchingDTO) {
        LOG.info("Argon2 match");
        return Response.ok().entity(argon2ServiceImpl.matches(passwordMatchingDTO)).build();
    }
}
