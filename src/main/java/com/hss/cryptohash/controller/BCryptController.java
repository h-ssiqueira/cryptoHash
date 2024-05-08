package com.hss.cryptohash.controller;

import com.hss.cryptohash.commons.BCryptRequestDTO;
import com.hss.cryptohash.commons.HashConfig;
import com.hss.cryptohash.commons.PasswordMatchingDTO;
import com.hss.cryptohash.domain.BcryptServiceImpl;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static jakarta.ws.rs.core.MediaType.APPLICATION_JSON;

@Path("/api/v1/bcrypt/")
public class BCryptController {

    private static final Logger LOG = LoggerFactory.getLogger(BCryptController.class);
    private final BcryptServiceImpl bcryptService;

    @Inject
    public BCryptController(BcryptServiceImpl bcryptService) {
        this.bcryptService = bcryptService;
    }

    @POST
    @Path("/encrypt")
    @Produces(APPLICATION_JSON)
    @Consumes(APPLICATION_JSON)
    Response encrypt(BCryptRequestDTO bCryptRequestDTO) {
        LOG.info("BCrypt encryption...");
        return Response.ok().entity(bcryptService.encrypt(HashConfig.builder().strength(bCryptRequestDTO.strength()).build(),bCryptRequestDTO.password())).build();
    }

    @POST
    @Path("match")
    @Produces(APPLICATION_JSON)
    @Consumes(APPLICATION_JSON)
    Response match(PasswordMatchingDTO passwordMatchingDTO) {
        LOG.info("BCrypt match");
        return Response.ok().entity(bcryptService.matches(passwordMatchingDTO)).build();
    }
}
