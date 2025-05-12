# CryptoHash
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Java 21](https://img.shields.io/badge/Java_21-000000?style=for-the-badge&logo=openjdk&logoColor=white)

![Quarkus](https://img.shields.io/badge/Quarkus-4695EB?style=for-the-badge&logo=quarkus&logoColor=white)
![Maven](https://img.shields.io/badge/Maven-C71A36?style=for-the-badge&logo=apachemaven&logoColor=white)

![junit5](https://img.shields.io/badge/junit5-25A162?style=for-the-badge&logo=junit5&logoColor=white)

- Encode and match passwords using hash functions.
## Executing
### Docker compose
```shell
docker-compose up --build
```
- Access the site [here](http://localhost:9999).
### Docker
#### JVM
- Generate image
```shell
docker build -f src/main/docker/Dockerfile.jvm -t quarkus/cryptohash-jvm .
```
- Execute
```shell
docker run -i --rm -p 8080:8080 quarkus/cryptohash-jvm
```
- Access the site [here](http://localhost:8080).
#### Legacy JAR
- Generate image
```shell
docker build -f src/main/docker/Dockerfile.legacy-jar -t quarkus/cryptohash-legacy-jar .
```
- Execute
```shell
docker run -i --rm -p 8080:8080 quarkus/cryptohash-legacy-jar
```
- Access the site [here](http://localhost:8080).
#### Native
- Generate image
```shell
docker build -f src/main/docker/Dockerfile.native -t quarkus/cryptohash .
```
- Execute
```shell
docker run -i --rm -p 8080:8080 quarkus/cryptohash
```
- Access the site [here](http://localhost:8080).
#### Native micro
- Generate image
```shell
docker build -f src/main/docker/Dockerfile.native-micro -t quarkus/cryptohash .
```
- Execute
```shell
docker run -i --rm -p 8080:8080 quarkus/cryptohash
```
- Access the site [here](http://localhost:8080).
### Command line
```shell script
./mvnw compile quarkus:dev
```
- Access the site [here](http://localhost:8080).
___
## Available Hash Algorithms

> Feel free to add more by opening a pull request.

Subgroup | Algorithm
:---: | :---:
BLAKE | BLAKE2B<br>BLAKE2BP<br>BLAKE2S<br>BLAKE2SP<br>BLAKE2XS<br>BLAKE3
Gost3411 | GOST3411<br>GOST3411_2012_256<br>GOST3411_2012_512
MD | MD2<br>MD4<br>MD5
Ripemd | RIPEMD128<br>RIPEMD160<br>RIPEMD256<br>RIPEMD320
Secure | ARGON2<br>BCRYPT<br>SCRYPT<br>PBKDF2
SHA | SHA1<br>SHA256<br>SHA3_224<br>SHA3_256<br>SHA3_384<br>SHA3_512<br>SHA384<br>SHA512_224<br>SHA512_256<br>SHA512
SHAKE | CSHAKE<br>SHAKE
Others | ASCON<br>DSTU7564<br>ISAP<br>KECCAK<br>PHOTONBEETLE<br>SKEIN<br>SM3<br>SPARKLE<br>TIGER<br>WHIRLPOOL<br>XOODYAK