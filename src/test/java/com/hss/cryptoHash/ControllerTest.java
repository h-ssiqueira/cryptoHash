package com.hss.cryptoHash;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.is;

@QuarkusTest
class ControllerTest {
    //@Test
    void testHelloEndpoint() {
        given()
          .when().post("localhost:8080/hash")
          .then()
             .statusCode(200)
             .body(is("Hello from RESTEasy Reactive"));
    }

}