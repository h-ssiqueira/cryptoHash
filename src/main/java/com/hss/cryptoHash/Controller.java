package com.hss.cryptoHash;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

import static jakarta.ws.rs.core.MediaType.TEXT_PLAIN;
import static org.springframework.security.crypto.password.Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA256;

@Path("/hash")
public class Controller {

    private final Argon2PasswordEncoder argon2PasswordEncoder = new Argon2PasswordEncoder(128/8, 256/8, 1, 10*1024, 10);
    private final BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
    private final SCryptPasswordEncoder sCryptPasswordEncoder = new SCryptPasswordEncoder(65536, 8, 1, 32, 16);
    private final Pbkdf2PasswordEncoder pbkdf2PasswordEncoder = new Pbkdf2PasswordEncoder("", 16, 310000, PBKDF2WithHmacSHA256);
    private final String length = " μs length: ";
    private final String time = "\nTime spent: ";

    // ./mvnw compile quarkus:dev:
    // curl -X POST -H "Content-Type: text/plain" -d 'admin' http://localhost:8080/hash
    @POST
    @Produces(TEXT_PLAIN)
    @Consumes(TEXT_PLAIN)
    public String showHashes(String password) {
        var response = new StringBuilder();
        var start = 0L;
        var end = 0L;
        var hash = "";

        response.append("Broken Hashes:\n\n");
        start = System.nanoTime();
        response.append("MD2: ").append(DigestUtils.md2Hex(password));
        end = System.nanoTime();
        response.append(time).append(calculateTime(start,end)).append(length);

        start = System.nanoTime();
        response.append("\n\nMD5: ").append(DigestUtils.md5Hex(password));
        end = System.nanoTime();
        response.append(time).append(calculateTime(start,end)).append(length);

        start = System.nanoTime();
        response.append("\n\nSHA1: ").append(DigestUtils.sha1Hex(password));
        end = System.nanoTime();
        response.append(time).append(calculateTime(start,end)).append(length);

        response.append("\n\n****************************\nCandidates:");

        start = System.nanoTime();
        hash = DigestUtils.sha256Hex(password);
        end = System.nanoTime();
        response.append("\n\nSHA256: ").append(hash);
        response.append(time).append(calculateTime(start,end)).append(length).append(hash.length());

        start = System.nanoTime();
        hash = DigestUtils.sha384Hex(password);
        end = System.nanoTime();
        response.append("\n\nSHA384: ").append(hash);
        response.append(time).append(calculateTime(start,end)).append(length).append(hash.length());

        start = System.nanoTime();
        hash = DigestUtils.sha512_224Hex(password);
        end = System.nanoTime();
        response.append("\n\nSHA512 224: ").append(hash);
        response.append(time).append(calculateTime(start,end)).append(length).append(hash.length());

        start = System.nanoTime();
        hash = DigestUtils.sha512_256Hex(password);
        end = System.nanoTime();
        response.append("\n\nSHA512 256: ").append(hash);
        response.append(time).append(calculateTime(start,end)).append(length).append(hash.length());

        start = System.nanoTime();
        hash = DigestUtils.sha512Hex(password);
        end = System.nanoTime();
        response.append("\n\nSHA512: ").append(hash);
        response.append(time).append(calculateTime(start,end)).append(length).append(hash.length());

        start = System.nanoTime();
        hash = DigestUtils.sha3_224Hex(password);
        end = System.nanoTime();
        response.append("\n\nSHA3 224: ").append(hash);
        response.append(time).append(calculateTime(start,end)).append(length).append(hash.length());

        start = System.nanoTime();
        hash = DigestUtils.sha3_256Hex(password);
        end = System.nanoTime();
        response.append("\n\nSHA3 256: ").append(hash);
        response.append(time).append(calculateTime(start,end)).append(length).append(hash.length());

        start = System.nanoTime();
        hash = DigestUtils.sha3_384Hex(password);
        end = System.nanoTime();
        response.append("\n\nSHA3 384: ").append(hash);
        response.append(time).append(calculateTime(start,end)).append(length).append(hash.length());

        start = System.nanoTime();
        hash = DigestUtils.sha3_512Hex(password);
        end = System.nanoTime();
        response.append("\n\nSHA3 512: ").append(hash);
        response.append(time).append(calculateTime(start,end)).append(length).append(hash.length());

        response.append("\n\n****************************\nRecommended with passwords:");

        start = System.nanoTime();
        hash = argon2PasswordEncoder.encode(password);
        end = System.nanoTime();
        response.append("\n\nArgon2: ").append(hash);
        response.append(time).append(calculateTime(start,end)).append(length).append(hash.length());

        start = System.nanoTime();
        hash = sCryptPasswordEncoder.encode(password);
        end = System.nanoTime();
        response.append("\n\nSCrypt: ").append(hash);
        response.append(time).append(calculateTime(start,end)).append(length).append(hash.length());

        start = System.nanoTime();
        hash = bCryptPasswordEncoder.encode(password);
        end = System.nanoTime();
        response.append("\n\nBCrypt: ").append(hash);
        response.append(time).append(calculateTime(start,end)).append(length).append(hash.length());

        start = System.nanoTime();
        hash = pbkdf2PasswordEncoder.encode(password);
        end = System.nanoTime();
        response.append("\n\nPBKDF2: ").append(hash);
        response.append(time).append(calculateTime(start,end)).append(length).append(hash.length());

        return response.append('\n').toString();
    }

    private long calculateTime(long start, long end){
        return (end-start) / 1000;
    }
}
