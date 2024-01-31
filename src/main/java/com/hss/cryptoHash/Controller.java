package com.hss.cryptoHash;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

import static jakarta.ws.rs.core.MediaType.TEXT_PLAIN;

@Path("/hash")
public class Controller {

    @POST
    @Produces(TEXT_PLAIN)
    @Consumes(TEXT_PLAIN)
    public String hello(String password) {
        int saltLength = 128 / 8; // 128 bits
        int hashLength = 256 / 8; // 256 bits
        int parallelism = 1;
        int memoryInKb = 10 * 1024; // 10 MB
        int iterations = 10;
        Argon2PasswordEncoder passwordEncoder = new Argon2PasswordEncoder(saltLength, hashLength, parallelism, memoryInKb, iterations);
        StringBuilder response = new StringBuilder();
        long start,end;

        start = System.nanoTime();
        response.append("MD2: ").append(DigestUtils.md2Hex(password));
        end = System.nanoTime();
        response.append("\nTime spent: ").append(calculateTime(start,end)).append("μs");

        start = System.nanoTime();
        response.append("\n\nMD5: ").append(DigestUtils.md5Hex(password));
        end = System.nanoTime();
        response.append("\nTime spent: ").append(calculateTime(start,end)).append("μs");

        start = System.nanoTime();
        response.append("\n\nSHA1: ").append(DigestUtils.sha1Hex(password));
        end = System.nanoTime();
        response.append("\nTime spent: ").append(calculateTime(start,end)).append("μs");

        start = System.nanoTime();
        response.append("\n\nSHA256: ").append(DigestUtils.sha256Hex(password));
        end = System.nanoTime();
        response.append("\nTime spent: ").append(calculateTime(start,end)).append("μs");

        start = System.nanoTime();
        response.append("\n\nSHA384: ").append(DigestUtils.sha384Hex(password));
        end = System.nanoTime();
        response.append("\nTime spent: ").append(calculateTime(start,end)).append("μs");

        start = System.nanoTime();
        response.append("\n\nSHA512 224: ").append(DigestUtils.sha512_224Hex(password));
        end = System.nanoTime();
        response.append("\nTime spent: ").append(calculateTime(start,end)).append("μs");

        start = System.nanoTime();
        response.append("\n\nSHA512 256: ").append(DigestUtils.sha512_256Hex(password));
        end = System.nanoTime();
        response.append("\nTime spent: ").append(calculateTime(start,end)).append("μs");

        start = System.nanoTime();
        response.append("\n\nSHA512: ").append(DigestUtils.sha512Hex(password));
        end = System.nanoTime();
        response.append("\nTime spent: ").append(calculateTime(start,end)).append("μs");

        start = System.nanoTime();
        response.append("\n\nSHA3 224: ").append(DigestUtils.sha3_224Hex(password));
        end = System.nanoTime();
        response.append("\nTime spent: ").append(calculateTime(start,end)).append("μs");

        start = System.nanoTime();
        response.append("\n\nSHA3 256: ").append(DigestUtils.sha3_256Hex(password));
        end = System.nanoTime();
        response.append("\nTime spent: ").append(calculateTime(start,end)).append("μs");

        start = System.nanoTime();
        response.append("\n\nSHA3 384: ").append(DigestUtils.sha3_384Hex(password));
        end = System.nanoTime();
        response.append("\nTime spent: ").append(calculateTime(start,end)).append("μs");

        start = System.nanoTime();
        response.append("\n\nSHA3 512: ").append(DigestUtils.sha3_512Hex(password));
        end = System.nanoTime();
        response.append("\nTime spent: ").append(calculateTime(start,end)).append("μs");

        start = System.nanoTime();
        response.append("\n\nArgon2: ").append(passwordEncoder.encode(password));
        end = System.nanoTime();
        response.append("\nTime spent: ").append(calculateTime(start,end)).append("μs");

        return response.append('\n').toString();
    }

    private long calculateTime(long start, long end){
        return (end-start) / 1000;
    }
}
