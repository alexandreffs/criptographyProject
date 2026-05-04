package secureUDPproxy;

import common.*;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.stream.Collectors;

public class secureUDPproxy {

    public static void main(String[] args) throws Exception {

        Map<String, CryptoConfig> configs = CryptoConfig.loadAll("Cryptoconfig.conf");

        Properties properties = new Properties();
        properties.load(new FileInputStream("secureUDPproxy/config.properties"));

        String remote = properties.getProperty("remote");
        String destinations = properties.getProperty("localdelivery");
        String serverControl = properties.getProperty("servercontrol");
        String movie = properties.getProperty("movie");

        SocketAddress inSocketAddress = parseSocketAddress(remote);
        SocketAddress serverControlAddress = parseSocketAddress(serverControl);

        Set<SocketAddress> outSocketAddressSet = Arrays.stream(destinations.split(","))
                .map(secureUDPproxy::parseSocketAddress)
                .collect(Collectors.toSet());

        DatagramSocket controlSocket = new DatagramSocket();
        DatagramSocket inSocket = new DatagramSocket(inSocketAddress);
        DatagramSocket outSocket = new DatagramSocket();

        System.out.println("Proxy listening on " + remote);

        String request = "REQUEST:" + movie + ":" + remote;
        byte[] requestBytes = request.getBytes();

        controlSocket.send(new DatagramPacket(
                requestBytes,
                requestBytes.length,
                serverControlAddress));

        System.out.println("Movie request sent: " + request);

        byte[] buffer = new byte[8192];

        CryptoConfig activeCrypto = null;

        int lastSequence = -1;
        int receivedFrames = 0;
        int droppedPackets = 0;

        long startTime = 0;

        while (true) {
            DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
            inSocket.receive(inPacket);

            byte[] packetData = Arrays.copyOfRange(inPacket.getData(), 0, inPacket.getLength());

            RTSSP.Packet packet;

            try {
                if (activeCrypto == null) {
                    DecryptionResult result = tryDecryptWithAllConfigs(packetData, configs);
                    packet = result.packet;
                    activeCrypto = result.crypto;
                } else {
                    packet = RTSSP.unprotect(packetData, activeCrypto);
                }
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
                System.out.println("START received: " + new String(packet.payload));
                System.out.println("CipherSuite selected: " + activeCrypto.cipherSuite);
            }

            else if (packet.type == RTSSP.TYPE_DATA) {
                receivedFrames++;

                for (SocketAddress outSocketAddress : outSocketAddressSet) {
                    outSocket.send(new DatagramPacket(packet.payload, packet.payload.length, outSocketAddress));
                }

                System.out.print(".");
            }

            else if (packet.type == RTSSP.TYPE_END) {
                long endTime = System.nanoTime();
                long duration = (endTime - startTime) / 1000000000;

                System.out.println();
                System.out.println("END received: " + new String(packet.payload));
                System.out.println("Frames received: " + receivedFrames);
                System.out.println("Packets dropped: " + droppedPackets);

                if (duration > 0) {
                    System.out.println("Throughput: " + receivedFrames / duration + " fps");
                }

                break;
            }

            else if (packet.type == RTSSP.TYPE_ERROR) {
                System.out.println("ERROR received: " + new String(packet.payload));
                break;
            }
        }

        controlSocket.close();
        inSocket.close();
        outSocket.close();
    }

    private static DecryptionResult tryDecryptWithAllConfigs(
            byte[] packetData,
            Map<String, CryptoConfig> configs) throws Exception {

        for (CryptoConfig crypto : configs.values()) {
            try {
                RTSSP.Packet packet = RTSSP.unprotect(packetData, crypto);

                if (packet.type == RTSSP.TYPE_START) {
                    return new DecryptionResult(packet, crypto);
                }
            } catch (Exception ignored) {
            }
        }

        throw new SecurityException("Could not decrypt packet with any configured movie key");
    }

    private static InetSocketAddress parseSocketAddress(String socketAddress) {
        String[] split = socketAddress.split(":");
        return new InetSocketAddress(split[0], Integer.parseInt(split[1]));
    }

    private static class DecryptionResult {
        RTSSP.Packet packet;
        CryptoConfig crypto;

        DecryptionResult(RTSSP.Packet packet, CryptoConfig crypto) {
            this.packet = packet;
            this.crypto = crypto;
        }
    }
}

// package secureUDPproxy;

// import java.io.*;
// import java.net.*;
// import java.util.*;
// import java.util.stream.Collectors;

// public class secureUDPproxy {

// public static void main(String[] args) throws Exception {

// Map<String, CryptoConfig> configs =
// CryptoConfig.loadAll("Cryptoconfig.conf");

// Properties properties = new Properties();
// properties.load(new FileInputStream("secureUDPproxy/config.properties"));

// String remote = properties.getProperty("remote");
// String destinations = properties.getProperty("localdelivery");

// SocketAddress inSocketAddress = parseSocketAddress(remote);

// Set<SocketAddress> outSocketAddressSet =
// Arrays.stream(destinations.split(","))
// .map(secureUDPproxy::parseSocketAddress)
// .collect(Collectors.toSet());

// DatagramSocket inSocket = new DatagramSocket(inSocketAddress);
// DatagramSocket outSocket = new DatagramSocket();

// byte[] buffer = new byte[8192];

// CryptoConfig activeCrypto = null;

// int lastSequence = -1;
// int receivedFrames = 0;
// int droppedPackets = 0;

// long startTime = 0;

// System.out.println("Proxy listening on " + remote);

// while (true) {
// DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
// inSocket.receive(inPacket);

// byte[] packetData = Arrays.copyOfRange(inPacket.getData(), 0,
// inPacket.getLength());

// RTSSP.Packet packet = null;

// try {
// if (activeCrypto == null) {
// DecryptionResult result = tryDecryptWithAllConfigs(packetData, configs);
// packet = result.packet;
// activeCrypto = result.crypto;
// } else {
// packet = RTSSP.unprotect(packetData, activeCrypto);
// }
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

// String msg = new String(packet.payload);

// System.out.println();
// System.out.println("START received: " + msg);
// System.out.println("CipherSuite selected: " + activeCrypto.cipherSuite);
// }

// else if (packet.type == RTSSP.TYPE_DATA) {
// receivedFrames++;

// for (SocketAddress outSocketAddress : outSocketAddressSet) {
// outSocket.send(new DatagramPacket(packet.payload, packet.payload.length,
// outSocketAddress));
// }

// System.out.print(".");
// }

// else if (packet.type == RTSSP.TYPE_END) {
// long endTime = System.nanoTime();
// long duration = (endTime - startTime) / 1000000000;

// System.out.println();
// System.out.println("END received: " + new String(packet.payload));
// System.out.println("Frames received: " + receivedFrames);
// System.out.println("Packets dropped: " + droppedPackets);

// if (duration > 0) {
// System.out.println("Throughput: " + receivedFrames / duration + " fps");
// }

// break;
// }

// else if (packet.type == RTSSP.TYPE_ERROR) {
// System.out.println("ERROR received: " + new String(packet.payload));
// break;
// }
// }

// inSocket.close();
// outSocket.close();
// }

// private static DecryptionResult tryDecryptWithAllConfigs(
// byte[] packetData,
// Map<String, CryptoConfig> configs) throws Exception {

// for (CryptoConfig crypto : configs.values()) {
// try {
// RTSSP.Packet packet = RTSSP.unprotect(packetData, crypto);

// if (packet.type == RTSSP.TYPE_START) {
// return new DecryptionResult(packet, crypto);
// }
// } catch (Exception ignored) {
// }
// }

// throw new SecurityException("Could not decrypt packet with any configured
// movie key");
// }

// private static InetSocketAddress parseSocketAddress(String socketAddress) {
// String[] split = socketAddress.split(":");
// String host = split[0];
// int port = Integer.parseInt(split[1]);
// return new InetSocketAddress(host, port);
// }

// private static class DecryptionResult {
// RTSSP.Packet packet;
// CryptoConfig crypto;

// DecryptionResult(RTSSP.Packet packet, CryptoConfig crypto) {
// this.packet = packet;
// this.crypto = crypto;
// }
// }
// }
