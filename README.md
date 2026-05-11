# Special Real-Time Media Streaming

## PA1 — RTSSP, SHP and PQ-SHP over UDP

This repository contains the implementation of a secure real-time media streaming system over UDP.

The project is divided into three parts:

```text
Part1-RTSSP          -> RTSSP/UDP with static cryptographic configuration
Part2-SHP-RTSSP      -> SHP/RTSSP/UDP with classical secure handshake
Part3-PQ-SHP-RTSSP   -> PQ-SHP/RTSSP/UDP with post-quantum handshake
```

The basic system is composed of:

```text
Streaming Server -> Secure UDP Proxy -> VLC
```

The server streams MPEG4-encoded frames stored in `.dat` movie files. The proxy receives the protected stream, verifies and decrypts it, then forwards the plaintext media frames locally to VLC.

---

# 1. Requirements

## Bouncy Castle for Part 3

Part 3 uses Bouncy Castle's post-quantum provider.

Place the Bouncy Castle JAR in the root of `Part3-PQ-SHP-RTSSP`.

Example:

```text
Part3-PQ-SHP-RTSSP/bcprov-jdk18on-1.84.jar
```

If you use a different version, update the compile and run commands accordingly.

---

# 2. Repository Structure

```text
SpecialRealTimeMediaStreaming/
|
|-- Part1-RTSSP/
|   |-- secureStreamServer/
|   |   |-- secureStreamServer.java
|   |   |-- RTSSP.java
|   |   |-- CryptoConfig.java
|   |   |-- movies/
|   |       |-- cars.dat
|   |
|   |-- secureUDPproxy/
|   |   |-- secureUDPproxy.java
|   |   |-- RTSSP.java
|   |   |-- CryptoConfig.java
|   |   |-- config.properties
|   |
|   |-- Cryptoconfig.conf
|   |-- README.md
|
|-- Part2-SHP-RTSSP/
|   |-- common/
|   |   |-- RTSSP.java
|   |   |-- CryptoConfig.java
|   |   |-- SHP.java
|   |   |-- SHPContext.java
|   |   |-- CertificateUtils.java
|   |
|   |-- secureStreamServer/
|   |   |-- secureStreamServer.java
|   |   |-- movies/
|   |       |-- cars.dat
|   |
|   |-- secureUDPproxy/
|   |   |-- secureUDPproxy.java
|   |   |-- config.properties
|   |
|   |-- server.cer
|   |-- proxy.cer
|   |-- README.md
|
|-- Part3-PQ-SHP-RTSSP/
|   |-- common/
|   |   |-- RTSSP.java
|   |   |-- CryptoConfig.java
|   |   |-- PQSHP.java
|   |   |-- PQSHPContext.java
|   |
|   |-- secureStreamServer/
|   |   |-- secureStreamServer.java
|   |   |-- movies/
|   |       |-- cars.dat
|   |
|   |-- secureUDPproxy/
|   |   |-- secureUDPproxy.java
|   |   |-- config.properties
|   |
|   |-- bcprov-jdk18on-1.84.jar
|   |-- README.md
|
|-- PA1_Report.pdf
|-- Part3_PQ_SHP_Report.pdf
|-- README.md
```

---

# 3. General VLC Setup

Before running the proxy, open VLC.

In VLC:

```text
Media -> Open Network Stream
```

Use:

```text
udp://@:7777
```

Then press **Play**.

Recommended execution order:

```text
1. Open VLC on udp://@:7777
2. Start the server
3. Start the proxy
```

The proxy forwards decrypted plaintext media frames to VLC through UDP port `7777`.

---

# 4. Part 1 — RTSSP/UDP

## 4.1 Description

Part 1 implements RTSSP, a secure real-time streaming protocol over UDP.

In this part, server and proxy share static cryptographic configurations through:

```text
Cryptoconfig.conf
```

RTSSP supports:

```text
START messages
DATA messages
END messages
ERROR messages
sequence numbers
replay protection
encrypted payloads
integrity verification
```

Supported ciphersuites include:

```text
AES/GCM/NoPadding
ChaCha20-Poly1305
AES/CTR/NoPadding + HmacSHA256
AES/CBC/PKCS5Padding + HmacSHA256, if configured
```

## 4.2 Part 1 Configuration

Example `secureUDPproxy/config.properties`:

```properties
remote=localhost:8888
localdelivery=localhost:7777

servercontrol=localhost:9999
movie=cars.dat
```

Meaning:

```text
remote          -> proxy receives protected RTSSP packets here
localdelivery   -> proxy forwards plaintext frames to VLC here
servercontrol   -> server waits for movie requests here
movie           -> requested movie
```

Example `Cryptoconfig.conf`:

```text
<cars.dat.encrypted>
ciphersuite: AES/GCM/NoPadding
key: 0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20
</cars.dat.encrypted>

<monsters.dat.encrypted>
ciphersuite: CHACHA20-Poly1305
key: 2122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F40
</monsters.dat.encrypted>
```

For AES-CTR with HMAC:

```text
<cars.dat.encrypted>
ciphersuite: AES/CTR/NoPadding
key: 0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20
hmac: HMACSHA256
mackey: A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0
</cars.dat.encrypted>
```

## 4.3 Compile Part 1

From the root of `Part1-RTSSP`:

```bash
javac common\*.java secureStreamServer\secureStreamServer.java secureUDPproxy\secureUDPproxy.java
```

## 4.4 Run Part 1

Open VLC first:

```text
udp://@:7777
```

Then, in a cmd terminal, start the server from `Part1-RTSSP`:

```bash
java -cp .;secureStreamServer secureStreamServer 9999
```

Then, in a cmd terminal, start the proxy from `Part1-RTSSP`:

```bash
java secureUDPproxy.secureUDPproxy
```

Expected server output:

```text
Server waiting for movie request on port 9999
Request received: REQUEST:cars.dat:localhost:8888
Movie: cars.dat
CipherSuite: AES/GCM/NoPadding
START sent
:::::::::::::::::::::::::
END sent
DONE! Frames sent: ...
```

Expected proxy output:

```text
Movie request sent: REQUEST:cars.dat:localhost:8888
Proxy listening on localhost:8888
START received: START:cars.dat
............................
END received: END:...
Frames received: ...
Packets dropped: 0
```

---

# 5. Part 2 — SHP/RTSSP/UDP

## 5.1 Description

Part 2 adds SHP, a classical secure handshake protocol for RTSSP.

Part 1 uses static symmetric keys. Part 2 removes that limitation by deriving fresh session keys dynamically.

SHP provides:

```text
ECDH key establishment
ECDSA signatures
X.509 certificates
server keystore
server truststore
proxy keystore
proxy truststore
dynamic ciphersuite negotiation
dynamic session key derivation
encrypted SHP_CLIENT_FINAL
RTSSP streaming with derived keys
```

The final stack is:

```text
SHP
RTSSP
UDP
```

## 5.2 Part 2 Configuration

Example `secureUDPproxy/config.properties`:

```properties
remote=localhost:8888
localdelivery=localhost:7777

servercontrol=localhost:9999
movie=cars.dat

supportedCiphersuites=AES/GCM/NoPadding,ChaCha20-Poly1305,AES/CTR/NoPadding
```

## 5.3 Generate Keystores and Truststores

Run these commands from the root of `Part2-SHP-RTSSP`.

### Server key pair and certificate

```bash
keytool -genkeypair -alias server -keyalg EC -groupname secp256r1 -sigalg SHA256withECDSA -keystore secureStreamServer/server-keystore.jks -storepass password -keypass password -dname "CN=StreamingServer" -validity 365
```

```bash
keytool -exportcert -alias server -keystore secureStreamServer/server-keystore.jks -storepass password -file server.cer
```

### Proxy key pair and certificate

```bash
keytool -genkeypair -alias proxy -keyalg EC -groupname secp256r1 -sigalg SHA256withECDSA -keystore secureUDPproxy/proxy-keystore.jks -storepass password -keypass password -dname "CN=ProxyBox" -validity 365
```

```bash
keytool -exportcert -alias proxy -keystore secureUDPproxy/proxy-keystore.jks -storepass password -file proxy.cer
```

### Import trusted certificates

Server trusts proxy:

```bash
keytool -importcert -alias proxy -file proxy.cer -keystore secureStreamServer/server-truststore.jks -storepass password -noprompt
```

Proxy trusts server:

```bash
keytool -importcert -alias server -file server.cer -keystore secureUDPproxy/proxy-truststore.jks -storepass password -noprompt
```

After this, the following files should exist:

```text
secureStreamServer/server-keystore.jks
secureStreamServer/server-truststore.jks

secureUDPproxy/proxy-keystore.jks
secureUDPproxy/proxy-truststore.jks
```

## 5.4 Compile Part 2

Compile from the root of `Part2-SHP-RTSSP`:

```bash
javac common\*.java secureStreamServer\secureStreamServer.java secureUDPproxy\secureUDPproxy.java
```

## 5.5 Run Part 2

Open VLC first:

```text
udp://@:7777
```

Then, in a cmd terminal, start the server from `Part2-SHP-RTSSP`:

```bash
java -cp ".;common;secureStreamServer" secureStreamServer 9999
```

Then, in a cmd terminal, start the proxy from `Part2-SHP-RTSSP`:

```bash
java secureUDPproxy.secureUDPproxy
```

Expected server output:

```text
Server waiting for signed SHP CLIENT_HELLO on port 9999
SHP CLIENT_HELLO received
Proxy certificate trusted
CLIENT_HELLO signature verified
SHP SERVER_HELLO sent and signed
Selected CipherSuite: AES/GCM/NoPadding
Session keys derived
SHP CLIENT_FINAL received and verified
SHP handshake completed with mutual authentication
Starting RTSSP stream...
RTSSP START sent
:::::::::::::::::::::::::::::
RTSSP END sent
DONE! Frames sent: ...
```

Expected proxy output:

```text
Proxy listening for RTSSP stream on localhost:8888
Starting SHP handshake with mutual authentication...
SHP CLIENT_HELLO sent and signed
SHP SERVER_HELLO received
Server certificate trusted
SERVER_HELLO signature verified
Selected CipherSuite: AES/GCM/NoPadding
Session keys derived
SHP CLIENT_FINAL sent encrypted
SHP handshake completed
Waiting for RTSSP stream...

RTSSP START received: START:cars.dat
............................
RTSSP END received: END:...
Frames received: ...
Packets dropped: 0
```

---

# 6. Part 3 — PQ-SHP/RTSSP/UDP

## 6.1 Description

Part 3 is the post-quantum extension.

It replaces the classical SHP asymmetric cryptography with post-quantum algorithms:

```text
ECDH   -> Crystals-Kyber / ML-KEM
ECDSA  -> Crystals-Dilithium / ML-DSA
```

The final stack is:

```text
PQ-SHP
RTSSP
UDP
```

RTSSP is reused. Only the handshake changes.

Part 3 provides:

```text
Kyber key encapsulation
Kyber decapsulation
Dilithium signatures
Dilithium signature verification
post-quantum session key derivation
dynamic ciphersuite negotiation
encrypted PQ_SHP_CLIENT_FINAL
RTSSP streaming with PQ-derived keys
```

## 6.2 Part 3 Configuration

Example `secureUDPproxy/config.properties`:

```properties
remote=localhost:8888
localdelivery=localhost:7777

servercontrol=localhost:9999
movie=cars.dat

supportedCiphersuites=AES/GCM/NoPadding,ChaCha20-Poly1305,AES/CTR/NoPadding
```

## 6.3 Compile Part 3

Make sure the Bouncy Castle JAR is present:

```text
Part3-PQ-SHP-RTSSP/bcprov-jdk18on-1.84.jar
```

From the root of `Part3-PQ-SHP-RTSSP`:

```bash
javac -cp ".;bcprov-jdk18on-1.84.jar" common/*.java secureStreamServer/*.java secureUDPproxy/*.java
```

## 6.4 Run Part 3

Open VLC first:

```text
udp://@:7777
```

Then, in a cmd terminal, start the server:

```bash
java -cp ".;bcprov-jdk18on-1.84.jar;secureStreamServer" secureStreamServer 9999
```

Then, in a cmd terminal, start the proxy:

```bash
java -cp ".;bcprov-jdk18on-1.84.jar;secureUDPproxy" secureUDPproxy.secureUDPproxy
```

Expected server output:

```text
Server waiting for signed PQ-SHP CLIENT_HELLO on port 9999
PQ-SHP CLIENT_HELLO received
PQ-SHP CLIENT_HELLO Dilithium signature verified
PQ-SHP SERVER_HELLO sent and signed
Selected CipherSuite: AES/GCM/NoPadding
Kyber shared secret established
RTSSP session keys derived
PQ-SHP CLIENT_FINAL received and verified
PQ-SHP handshake completed
Starting RTSSP stream...
RTSSP START sent
:::::::::::::::::::::::::::::
RTSSP END sent
DONE! Frames sent: ...
```

Expected proxy output:

```text
Proxy listening for RTSSP stream on localhost:8888
Starting PQ-SHP handshake...
PQ-SHP CLIENT_HELLO sent and signed
PQ-SHP SERVER_HELLO received
SERVER_HELLO Dilithium signature verified
Selected CipherSuite: AES/GCM/NoPadding
Kyber shared secret decapsulated
RTSSP session keys derived
PQ-SHP CLIENT_FINAL sent encrypted
PQ-SHP handshake completed
Waiting for RTSSP stream...

RTSSP START received: START:cars.dat
............................
RTSSP END received: END:...
Frames received: ...
Packets dropped: 0
```

---

# 7. Authors

```text
Alexandre Santos 72970
Miguel Mestre 73018
```
