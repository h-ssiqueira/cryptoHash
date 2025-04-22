package com.hss.cryptohash.controller;

import com.hss.cryptohash.commons.dto.AlgorithmListResponseDTO;
import com.hss.cryptohash.commons.dto.EncryptionRequestDTO;
import com.hss.cryptohash.commons.dto.GeneralResponseDTO;
import com.hss.cryptohash.commons.dto.PasswordMatchingRequestDTO;
import com.hss.cryptohash.commons.exception.CryptoHashException;
import com.hss.cryptohash.commons.strategy.Algorithm.AlgorithmStrategyEnum;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.validation.Valid;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Response;
import lombok.extern.slf4j.Slf4j;

import java.util.Arrays;

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
    public Response encrypt(@Valid EncryptionRequestDTO encryptionRequestDTO, @QueryParam(value = "algorithm") String algorithm) throws CryptoHashException {
        try{
            log.debug("{} encryption", algorithm);
            cryptoHashDelegate.setStrategy(algorithm);
            return Response.ok().entity(new GeneralResponseDTO<>(cryptoHashDelegate.encrypt(encryptionRequestDTO))).build();
        } catch (Exception ex) {
            log.error(ex.getMessage());
            throw new CryptoHashException(ex);
        }
    }

    @POST
    @Path("/match")
    @Produces(APPLICATION_JSON)
    @Consumes(APPLICATION_JSON)
    public Response match(@Valid PasswordMatchingRequestDTO passwordMatchingRequestDTO, @QueryParam(value = "algorithm") String algorithm) throws CryptoHashException {
        try {
            log.debug("{} match", algorithm);
            cryptoHashDelegate.setStrategy(algorithm);
            return Response.ok(new GeneralResponseDTO<>(cryptoHashDelegate.match(passwordMatchingRequestDTO))).build();
        } catch (Exception ex) {
            log.error(ex.getMessage());
            throw new CryptoHashException(ex);
        }
    }

    @GET
    @Path("/algorithms")
    @Produces(APPLICATION_JSON)
    public Response getAlgorithms() {
        var list = Arrays.stream(AlgorithmStrategyEnum.values()).map(AlgorithmStrategyEnum::toString).sorted().toList();
        return Response.ok().entity(new GeneralResponseDTO<>(new AlgorithmListResponseDTO(list))).build();
    }

}