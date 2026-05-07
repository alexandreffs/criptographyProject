package secureUDPproxy;

import common.*;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import java.util.stream.Collectors;

public class secureUDPproxy {

    /*
     * Optional trust pinning.
     *
     * If null, the proxy accepts any server Dilithium public key that correctly
     * verifies the SERVER_HELLO signature.
     *
     * For stronger authentication, run once, copy the server Dilithium fingerprint
     * printed in the server terminal, and paste it here.
     */
    private static final String EXPECTED_SERVER_DILITHIUM_FINGERPRINT = "9Ob+E4Ut2P75w6WZJcjdDpl5XJ1JU9DDf+81RSn2EnY=";

    public static void main(String[] args) throws Exception {

        Properties properties = new Properties();
        properties.load(new FileInputStream("secureUDPproxy/config.properties"));

        String remote = properties.getProperty("remote");
        String destinations = properties.getProperty("localdelivery");
        String serverControl = properties.getProperty("servercontrol");
        String movieName = properties.getProperty("movie");

        String[] clientSupportedCipherSuites = properties.getProperty("supportedCiphersuites").split(",");

        SocketAddress inSocketAddress = parseSocketAddress(remote);
        SocketAddress serverControlAddress = parseSocketAddress(serverControl);

        Set<SocketAddress> outSocketAddressSet = Arrays.stream(destinations.split(","))
                .map(secureUDPproxy::parseSocketAddress)
                .collect(Collectors.toSet());

        DatagramSocket controlSocket = new DatagramSocket();
        DatagramSocket inSocket = new DatagramSocket(inSocketAddress);
        DatagramSocket outSocket = new DatagramSocket();

        System.out.println("Proxy listening for RTSSP stream on " + remote);
        System.out.println("Starting PQ-SHP handshake...");

        /*
         * ============================================================
         * 1. GENERATE KYBER AND DILITHIUM KEYPAIRS
         * ============================================================
         */

        KeyPair clientKyberKeyPair = PQSHP.generateKyberKeyPair();
        KeyPair clientDilithiumKeyPair = PQSHP.generateDilithiumKeyPair();

        String proxyFingerprint = PQSHP.publicKeyFingerprint(clientDilithiumKeyPair.getPublic());
        System.out.println("Proxy Dilithium public key fingerprint: " + proxyFingerprint);

        byte[] clientNonce = PQSHP.generateNonce();

        /*
         * ============================================================
         * 2. SEND SIGNED PQ-SHP CLIENT_HELLO
         * ============================================================
         */

        String clientHello = PQSHP.createClientHello(
                movieName,
                remote,
                clientSupportedCipherSuites,
                clientKyberKeyPair.getPublic(),
                clientNonce,
                clientDilithiumKeyPair.getPublic(),
                clientDilithiumKeyPair.getPrivate());

        byte[] clientHelloBytes = clientHello.getBytes();

        controlSocket.send(new DatagramPacket(
                clientHelloBytes,
                clientHelloBytes.length,
                serverControlAddress));

        System.out.println("PQ-SHP CLIENT_HELLO sent and signed");

        /*
         * ============================================================
         * 3. RECEIVE PQ-SHP SERVER_HELLO
         * ============================================================
         */

        byte[] responseBuffer = new byte[65507];
        DatagramPacket responsePacket = new DatagramPacket(responseBuffer, responseBuffer.length);

        controlSocket.receive(responsePacket);

        String serverHello = new String(
                responsePacket.getData(),
                0,
                responsePacket.getLength());

        if (serverHello.startsWith(PQSHP.PQ_ERROR)) {
            System.out.println("Server error: " + serverHello);
            closeSockets(controlSocket, inSocket, outSocket);
            return;
        }

        String[] serverParts = PQSHP.splitMessage(serverHello);

        if (!serverParts[0].equals(PQSHP.PQ_SERVER_HELLO)) {
            throw new SecurityException("Invalid PQ-SHP SERVER_HELLO");
        }

        if (!PQSHP.verifyServerHelloSignature(serverParts)) {
            throw new SecurityException("Invalid PQ-SHP SERVER_HELLO Dilithium signature");
        }

        String confirmedMovieName = serverParts[1];
        String selectedCipherSuite = serverParts[2];
        byte[] serverNonce = PQSHP.base64ToBytes(serverParts[3]);
        byte[] kyberEncapsulation = PQSHP.base64ToBytes(serverParts[4]);
        PublicKey serverDilithiumPublicKey = PQSHP.base64ToDilithiumPublicKey(serverParts[5]);
        byte[] clientNonceResponse = PQSHP.base64ToBytes(serverParts[6]);

        String serverFingerprint = PQSHP.publicKeyFingerprint(serverDilithiumPublicKey);
        System.out.println("Server Dilithium public key fingerprint: " + serverFingerprint);

        if (EXPECTED_SERVER_DILITHIUM_FINGERPRINT != null) {
            PQSHP.verifyExpectedFingerprint(
                    serverDilithiumPublicKey,
                    EXPECTED_SERVER_DILITHIUM_FINGERPRINT);
            System.out.println("Server Dilithium fingerprint trusted");
        }

        if (!confirmedMovieName.equals(movieName)) {
            throw new SecurityException("Server confirmed wrong movie name");
        }

        if (!PQSHP.verifyNonceResponse(clientNonce, clientNonceResponse)) {
            throw new SecurityException("Invalid response to client nonce");
        }

        System.out.println("PQ-SHP SERVER_HELLO received");
        System.out.println("SERVER_HELLO Dilithium signature verified");
        System.out.println("Selected CipherSuite: " + selectedCipherSuite);

        /*
         * ============================================================
         * 4. KYBER DECAPSULATION
         * ============================================================
         */

        byte[] kyberSharedSecret = PQSHP.kyberDecapsulate(
                clientKyberKeyPair.getPrivate(),
                kyberEncapsulation);

        /*
         * ============================================================
         * 5. DERIVE RTSSP SESSION KEYS
         * ============================================================
         */

        PQSHPContext pqContext = new PQSHPContext();
        pqContext.movieName = movieName;
        pqContext.selectedCipherSuite = selectedCipherSuite;
        pqContext.clientNonce = clientNonce;
        pqContext.serverNonce = serverNonce;
        pqContext.kyberSharedSecret = kyberSharedSecret;

        pqContext.encryptionKey = PQSHP.deriveEncryptionKey(
                kyberSharedSecret,
                clientNonce,
                serverNonce,
                selectedCipherSuite);

        if (PQSHP.needsMacKey(selectedCipherSuite)) {
            pqContext.macKey = PQSHP.deriveMacKey(
                    kyberSharedSecret,
                    clientNonce,
                    serverNonce);
        }

        CryptoConfig activeCrypto = pqContext.toCryptoConfig();

        System.out.println("Kyber shared secret decapsulated");
        System.out.println("RTSSP session keys derived");

        /*
         * ============================================================
         * 6. SEND ENCRYPTED PQ-SHP CLIENT_FINAL
         * ============================================================
         */

        byte[] serverNonceResponse = PQSHP.createNonceResponse(serverNonce);
        String clientFinal = PQSHP.createClientFinal(serverNonceResponse);

        byte[] protectedClientFinal = RTSSP.protect(
                RTSSP.TYPE_DATA,
                0,
                clientFinal.getBytes(),
                activeCrypto);

        controlSocket.send(new DatagramPacket(
                protectedClientFinal,
                protectedClientFinal.length,
                serverControlAddress));

        System.out.println("PQ-SHP CLIENT_FINAL sent encrypted");
        System.out.println("PQ-SHP handshake completed");
        System.out.println("Waiting for RTSSP stream...");

        /*
         * ============================================================
         * 7. RECEIVE RTSSP STREAM
         * ============================================================
         */

        receiveStream(inSocket, outSocket, outSocketAddressSet, activeCrypto);

        closeSockets(controlSocket, inSocket, outSocket);
    }

    private static void receiveStream(
            DatagramSocket inSocket,
            DatagramSocket outSocket,
            Set<SocketAddress> outSocketAddressSet,
            CryptoConfig activeCrypto) throws Exception {

        byte[] buffer = new byte[8192];

        int lastSequence = -1;
        int receivedFrames = 0;
        int droppedPackets = 0;

        long startTime = 0;

        while (true) {
            DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
            inSocket.receive(inPacket);

            byte[] packetData = Arrays.copyOfRange(
                    inPacket.getData(),
                    0,
                    inPacket.getLength());

            RTSSP.Packet packet;

            try {
                packet = RTSSP.unprotect(packetData, activeCrypto);
            } catch (Exception e) {
                droppedPackets++;
                System.out.print("X");
                continue;
            }

            if (packet.sequenceNumber <= lastSequence) {
                droppedPackets++;
                System.out.print("R");
                continue;
            }

            lastSequence = packet.sequenceNumber;

            if (packet.type == RTSSP.TYPE_START) {
                startTime = System.nanoTime();
                receivedFrames = 0;
                droppedPackets = 0;

                System.out.println();
                System.out.println("RTSSP START received: " + new String(packet.payload));
            }

            else if (packet.type == RTSSP.TYPE_DATA) {
                receivedFrames++;

                for (SocketAddress outSocketAddress : outSocketAddressSet) {
                    outSocket.send(new DatagramPacket(
                            packet.payload,
                            packet.payload.length,
                            outSocketAddress));
                }

                System.out.print(".");
            }

            else if (packet.type == RTSSP.TYPE_END) {
                long endTime = System.nanoTime();
                long duration = (endTime - startTime) / 1000000000;

                System.out.println();
                System.out.println("RTSSP END received: " + new String(packet.payload));
                System.out.println("Frames received: " + receivedFrames);
                System.out.println("Packets dropped: " + droppedPackets);

                if (duration > 0) {
                    System.out.println("Throughput: " + receivedFrames / duration + " fps");
                }

                break;
            }

            else if (packet.type == RTSSP.TYPE_ERROR) {
                System.out.println("RTSSP ERROR received: " + new String(packet.payload));
                break;
            }
        }
    }

    private static InetSocketAddress parseSocketAddress(String socketAddress) {
        String[] split = socketAddress.split(":");
        return new InetSocketAddress(split[0], Integer.parseInt(split[1]));
    }

    private static void closeSockets(
            DatagramSocket controlSocket,
            DatagramSocket inSocket,
            DatagramSocket outSocket) {
        controlSocket.close();
        inSocket.close();
        outSocket.close();
    }
}

// package secureUDPproxy;

// import java.io.*;
// import java.net.*;
// import java.security.*;
// import java.util.*;
// import java.util.stream.Collectors;

// public class secureUDPproxy {

// public static void main(String[] args) throws Exception {

// Properties properties = new Properties();
// properties.load(new FileInputStream("secureUDPproxy/config.properties"));

// String remote = properties.getProperty("remote");
// String destinations = properties.getProperty("localdelivery");
// String serverControl = properties.getProperty("servercontrol");
// String movieName = properties.getProperty("movie");

// String[] clientSupportedCipherSuites =
// properties.getProperty("supportedCiphersuites").split(",");

// SocketAddress inSocketAddress = parseSocketAddress(remote);
// SocketAddress serverControlAddress = parseSocketAddress(serverControl);

// Set<SocketAddress> outSocketAddressSet =
// Arrays.stream(destinations.split(","))
// .map(secureUDPproxy::parseSocketAddress)
// .collect(Collectors.toSet());

// DatagramSocket controlSocket = new DatagramSocket();
// DatagramSocket inSocket = new DatagramSocket(inSocketAddress);
// DatagramSocket outSocket = new DatagramSocket();

// System.out.println("Proxy listening for RTSSP stream on " + remote);

// /*
// * ============================
// * SHP CLIENT SIDE HANDSHAKE
// * ============================
// */

// System.out.println("Starting SHP handshake...");

// KeyPair clientECDHKeyPair = SHP.generateECDHKeyPair();
// byte[] clientNonce = SHP.generateNonce();

// String clientHello = SHP.createClientHello(
// movieName,
// clientSupportedCipherSuites,
// clientECDHKeyPair.getPublic(),
// clientNonce);

// byte[] clientHelloBytes = clientHello.getBytes();

// controlSocket.send(new DatagramPacket(
// clientHelloBytes,
// clientHelloBytes.length,
// serverControlAddress));

// System.out.println("SHP CLIENT_HELLO sent");

// byte[] responseBuffer = new byte[8192];
// DatagramPacket responsePacket = new DatagramPacket(responseBuffer,
// responseBuffer.length);

// controlSocket.receive(responsePacket);

// String serverHello = new String(
// responsePacket.getData(),
// 0,
// responsePacket.getLength());

// if (serverHello.startsWith("SHP_ERROR")) {
// System.out.println("Server error: " + serverHello);
// controlSocket.close();
// inSocket.close();
// outSocket.close();
// return;
// }

// String[] serverParts = SHP.splitMessage(serverHello);

// if (!serverParts[0].equals(SHP.SHP_SERVER_HELLO)) {
// throw new RuntimeException("Invalid SHP SERVER_HELLO");
// }

// String confirmedMovieName = serverParts[1];
// String selectedCipherSuite = serverParts[2];
// PublicKey serverECDHPublicKey = SHP.base64ToPublicKey(serverParts[3]);
// byte[] serverNonce = SHP.base64ToBytes(serverParts[4]);
// byte[] clientNonceResponse = SHP.base64ToBytes(serverParts[5]);

// if (!confirmedMovieName.equals(movieName)) {
// throw new SecurityException("Server confirmed wrong movie name");
// }

// if (!SHP.verifyNonceResponse(clientNonce, clientNonceResponse)) {
// throw new SecurityException("Invalid response to client nonce");
// }

// byte[] sharedSecret = SHP.computeSharedSecret(
// clientECDHKeyPair.getPrivate(),
// serverECDHPublicKey);

// SHPContext shpContext = new SHPContext();
// shpContext.movieName = movieName;
// shpContext.selectedCipherSuite = selectedCipherSuite;
// shpContext.clientNonce = clientNonce;
// shpContext.serverNonce = serverNonce;

// shpContext.encryptionKey = SHP.deriveEncryptionKey(
// sharedSecret,
// clientNonce,
// serverNonce,
// selectedCipherSuite);

// if (SHP.needsMacKey(selectedCipherSuite)) {
// shpContext.macKey = SHP.deriveMacKey(
// sharedSecret,
// clientNonce,
// serverNonce);
// }

// CryptoConfig activeCrypto = shpContext.toCryptoConfig();

// System.out.println("SHP SERVER_HELLO received");
// System.out.println("Selected CipherSuite: " + selectedCipherSuite);
// System.out.println("Session keys derived");

// byte[] serverNonceResponse = SHP.createNonceResponse(serverNonce);
// String clientFinal = SHP.createClientFinal(serverNonceResponse);

// byte[] protectedClientFinal = RTSSP.protect(
// RTSSP.TYPE_DATA,
// 0,
// clientFinal.getBytes(),
// activeCrypto);

// controlSocket.send(new DatagramPacket(
// protectedClientFinal,
// protectedClientFinal.length,
// serverControlAddress));

// System.out.println("SHP CLIENT_FINAL sent");
// System.out.println("SHP handshake completed");
// System.out.println("Waiting for RTSSP stream...");

// /*
// * ============================
// * RTSSP STREAM RECEPTION
// * ============================
// */

// byte[] buffer = new byte[8192];

// int lastSequence = -1;
// int receivedFrames = 0;
// int droppedPackets = 0;

// long startTime = 0;

// while (true) {
// DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
// inSocket.receive(inPacket);

// byte[] packetData = Arrays.copyOfRange(
// inPacket.getData(),
// 0,
// inPacket.getLength());

// RTSSP.Packet packet;

// try {
// packet = RTSSP.unprotect(packetData, activeCrypto);
// } catch (Exception e) {
// droppedPackets++;
// System.out.print("X");
// continue;
// }

// if (packet.sequenceNumber <= lastSequence) {
// droppedPackets++;
// System.out.print("R");
// continue;
// }

// lastSequence = packet.sequenceNumber;

// if (packet.type == RTSSP.TYPE_START) {
// startTime = System.nanoTime();
// receivedFrames = 0;
// droppedPackets = 0;

// System.out.println();
// System.out.println("RTSSP START received: " + new String(packet.payload));
// }

// else if (packet.type == RTSSP.TYPE_DATA) {
// receivedFrames++;

// for (SocketAddress outSocketAddress : outSocketAddressSet) {
// outSocket.send(new DatagramPacket(
// packet.payload,
// packet.payload.length,
// outSocketAddress));
// }

// System.out.print(".");
// }

// else if (packet.type == RTSSP.TYPE_END) {
// long endTime = System.nanoTime();
// long duration = (endTime - startTime) / 1000000000;

// System.out.println();
// System.out.println("RTSSP END received: " + new String(packet.payload));
// System.out.println("Frames received: " + receivedFrames);
// System.out.println("Packets dropped: " + droppedPackets);

// if (duration > 0) {
// System.out.println("Throughput: " + receivedFrames / duration + " fps");
// }

// break;
// }

// else if (packet.type == RTSSP.TYPE_ERROR) {
// System.out.println("RTSSP ERROR received: " + new String(packet.payload));
// break;
// }
// }

// controlSocket.close();
// inSocket.close();
// outSocket.close();
// }

// private static InetSocketAddress parseSocketAddress(String socketAddress) {
// String[] split = socketAddress.split(":");
// return new InetSocketAddress(split[0], Integer.parseInt(split[1]));
// }
// }
