package com.hss.cryptohash.integration;

import com.hss.cryptohash.commons.strategy.AlgorithmStrategyEnum;
import io.quarkus.test.junit.QuarkusTest;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import static io.restassured.RestAssured.given;
import static jakarta.ws.rs.core.MediaType.APPLICATION_JSON;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;

@Slf4j
@QuarkusTest
class ControllerTest {

    private static final String BASE_URL = "http://localhost:8080/api/v1/%s";
    static final List<String> ALGORITHMS = Arrays.stream(AlgorithmStrategyEnum.values()).map(AlgorithmStrategyEnum::toString).sorted().toList();

    @Test
    @DisplayName("Should Validate Available Algorithms")
    void shouldValidateAvailableHashingAlgorithms() {
        given()
        .when()
            .get(BASE_URL.formatted("algorithms"))
        .then()
             .statusCode(200)
             .body("data.algorithms", hasSize(ALGORITHMS.size()))
             .body("data.algorithms", equalTo(ALGORITHMS))
             .log().everything();
    }

    @ParameterizedTest(name = "with {0}")
    @MethodSource("getAlgorithms")
    @DisplayName("Should Validate And Match Algorithm Hashing")
    void shouldValidateAndMatchAlgorithmHashing(String algorithm) {
        var password = "admin";
        var encrypted = given()
            .body("""
                     {
                         "password": "%s"
                     }""".formatted(password))
            .contentType(APPLICATION_JSON)
            .queryParam("algorithm", algorithm)
        .when()
            .post(BASE_URL.formatted("encrypt"))
        .then()
            .statusCode(200)
            .log().everything()
            .extract().response().body().jsonPath().get("data.passwordEncrypted");

        given()
            .body("""
                    {
                        "rawPassword": "%s",
                        "encryptedPassword": "%s"
                    }""".formatted(password,encrypted))
            .contentType(APPLICATION_JSON)
            .queryParam("algorithm", algorithm)
        .when()
            .post(BASE_URL.formatted("match"))
        .then()
            .statusCode(200)
            .log().everything();
    }

    private static Stream<Arguments> getAlgorithms() {
        return ALGORITHMS.stream().map(Arguments::of);
    }
}