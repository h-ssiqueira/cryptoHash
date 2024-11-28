package com.hss.cryptoHash;

import io.quarkus.test.junit.QuarkusTest;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

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
    static final List<String> ALGORITHMS = List.of("ARGON2", "BCRYPT", "SCRYPT", "PBKDF2", "MD2", "MD5", "SHA1", "SHA256", "SHA3_224", "SHA3_256", "SHA3_384", "SHA3_512", "SHA384", "SHA512_224", "SHA512_256", "SHA512", "BLAKE3");

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
        var encrypted = given()
            .body("""
                     {
                         "password": "admin"
                     }""")
            .contentType(APPLICATION_JSON)
            .queryParam("algorithm", algorithm)
        .when()
            .post(BASE_URL.formatted("encrypt"))
        .then()
            .statusCode(200)
            .log().everything()
            .extract().response().body().jsonPath().get("data.passwordEncrypted");
        log.info(encrypted.toString());
        given()
            .body("""
                    {
                        "rawPassword": "admin"
                        "encryptedPassword": "%s"
                    }""".formatted(encrypted))
            .contentType(APPLICATION_JSON)
            .queryParam("algorithm", algorithm)
        .when()
            .post(BASE_URL.formatted("match"))
        .then()
            .statusCode(200)
            .log().everything()
            .body("data.match", equalTo(true));
    }

    private static Stream<Arguments> getAlgorithms() {
        return ALGORITHMS.stream().map(Arguments::of);
    }
}