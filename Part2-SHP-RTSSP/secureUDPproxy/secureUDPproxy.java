package secureUDPproxy;

import common.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;

public class secureUDPproxy {

    private static final String PROXY_KEYSTORE = "secureUDPproxy/proxy-keystore.jks";
    private static final String PROXY_TRUSTSTORE = "secureUDPproxy/proxy-truststore.jks";
    private static final String PASSWORD = "password";
    private static final String PROXY_ALIAS = "proxy";
    private static final String SERVER_ALIAS = "server";

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

        PrivateKey proxyPrivateKey = CertificateUtils.loadPrivateKey(
                PROXY_KEYSTORE,
                PASSWORD,
                PROXY_ALIAS,
                PASSWORD);

        X509Certificate proxyCertificate = CertificateUtils.loadCertificateFromKeystore(
                PROXY_KEYSTORE,
                PASSWORD,
                PROXY_ALIAS);

        X509Certificate trustedServerCertificate = CertificateUtils.loadTrustedCertificate(
                PROXY_TRUSTSTORE,
                PASSWORD,
                SERVER_ALIAS);

        DatagramSocket controlSocket = new DatagramSocket();
        DatagramSocket inSocket = new DatagramSocket(inSocketAddress);
        DatagramSocket outSocket = new DatagramSocket();

        System.out.println("Proxy listening for RTSSP stream on " + remote);
        System.out.println("Starting SHP handshake with mutual authentication...");

        KeyPair clientECDHKeyPair = SHP.generateECDHKeyPair();
        byte[] clientNonce = SHP.generateNonce();

        String clientHello = SHP.createClientHello(
                movieName,
                remote,
                clientSupportedCipherSuites,
                clientECDHKeyPair.getPublic(),
                clientNonce,
                proxyCertificate,
                proxyPrivateKey);

        byte[] clientHelloBytes = clientHello.getBytes();

        controlSocket.send(new DatagramPacket(
                clientHelloBytes,
                clientHelloBytes.length,
                serverControlAddress));

        System.out.println("SHP CLIENT_HELLO sent and signed");

        byte[] responseBuffer = new byte[16384];

        DatagramPacket responsePacket = new DatagramPacket(responseBuffer, responseBuffer.length);

        controlSocket.receive(responsePacket);

        String serverHello = new String(
                responsePacket.getData(),
                0,
                responsePacket.getLength());

        if (serverHello.startsWith(SHP.SHP_ERROR)) {
            System.out.println("Server error: " + serverHello);
            closeSockets(controlSocket, inSocket, outSocket);
            return;
        }

        String[] serverParts = SHP.splitMessage(serverHello);

        if (!serverParts[0].equals(SHP.SHP_SERVER_HELLO)) {
            throw new SecurityException("Invalid SHP SERVER_HELLO");
        }

        if (!SHP.verifyServerHelloSignature(serverParts)) {
            throw new SecurityException("Invalid SERVER_HELLO signature");
        }

        X509Certificate receivedServerCertificate = SHP.base64ToCertificate(serverParts[6]);

        CertificateUtils.verifyCertificateIsTrusted(
                receivedServerCertificate,
                trustedServerCertificate);

        String confirmedMovieName = serverParts[1];
        String selectedCipherSuite = serverParts[2];
        PublicKey serverECDHPublicKey = SHP.base64ToPublicKey(serverParts[3]);
        byte[] serverNonce = SHP.base64ToBytes(serverParts[4]);
        byte[] clientNonceResponse = SHP.base64ToBytes(serverParts[5]);

        if (!confirmedMovieName.equals(movieName)) {
            throw new SecurityException("Server confirmed wrong movie name");
        }

        if (!SHP.verifyNonceResponse(clientNonce, clientNonceResponse)) {
            throw new SecurityException("Invalid response to client nonce");
        }

        byte[] sharedSecret = SHP.computeSharedSecret(
                clientECDHKeyPair.getPrivate(),
                serverECDHPublicKey);

        SHPContext shpContext = new SHPContext();
        shpContext.movieName = movieName;
        shpContext.selectedCipherSuite = selectedCipherSuite;
        shpContext.clientNonce = clientNonce;
        shpContext.serverNonce = serverNonce;

        shpContext.encryptionKey = SHP.deriveEncryptionKey(
                sharedSecret,
                clientNonce,
                serverNonce,
                selectedCipherSuite);

        if (SHP.needsMacKey(selectedCipherSuite)) {
            shpContext.macKey = SHP.deriveMacKey(
                    sharedSecret,
                    clientNonce,
                    serverNonce);
        }

        CryptoConfig activeCrypto = shpContext.toCryptoConfig();

        System.out.println("SHP SERVER_HELLO received");
        System.out.println("Server certificate trusted");
        System.out.println("SERVER_HELLO signature verified");
        System.out.println("Selected CipherSuite: " + selectedCipherSuite);
        System.out.println("Session keys derived");

        byte[] serverNonceResponse = SHP.createNonceResponse(serverNonce);
        String clientFinal = SHP.createClientFinal(serverNonceResponse);

        byte[] protectedClientFinal = RTSSP.protect(
                RTSSP.TYPE_DATA,
                0,
                clientFinal.getBytes(),
                activeCrypto);

        controlSocket.send(new DatagramPacket(
                protectedClientFinal,
                protectedClientFinal.length,
                serverControlAddress));

        System.out.println("SHP CLIENT_FINAL sent encrypted");
        System.out.println("SHP handshake completed");
        System.out.println("Waiting for RTSSP stream...");

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
