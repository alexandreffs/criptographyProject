/* secureUDPproxy
 *
 * This is a very simple (transparent) UDP proxy
 * The proxy can listening on a remote source (server) UDP sender
 * and transparently forward received datagram packets in the
 * delivering endpoint
 *
 * Possible Remote listening endpoints:
 *    Unicast IP address and port: configurable in the file config.properties
 *    Multicast IP address and port: configurable in the code
 *  
 * Possible local listening endpoints:
 *    Unicast IP address and port
 *    Multicast IP address and port
 *       Both configurable in the file config.properties
 */

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.Key;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class secureUDPproxy {

    private static final int NONCE_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;

    public static void main(String[] args) throws Exception {

        if (args.length != 1) {
            System.out.println("Erro, usar: java secureUDPproxy <encrypt-scheme>");
            System.exit(-1);
        }

        String algorithm = args[0]; // usar "CHACHA "ou "AES"

        // Shared key between server and proxy
        // The same bytes must be used in the server
        SecretKey key;
        if (algorithm.equals("AES")) {
            byte[] keyBytes = new byte[] {
                    0x01, 0x02, 0x03, 0x04,
                    0x05, 0x06, 0x07, 0x08,
                    0x09, 0x0A, 0x0B, 0x0C,
                    0x0D, 0x0E, 0x0F, 0x10,
                    0x11, 0x12, 0x13, 0x14,
                    0x15, 0x16, 0x17, 0x18,
                    0x19, 0x1A, 0x1B, 0x1C,
                    0x1D, 0x1E, 0x1F, 0x20
            };
            key = new SecretKeySpec(keyBytes, "AES");
        } else {
            byte[] keyBytes = new byte[] {
                    0x21, 0x22, 0x23, 0x24,
                    0x25, 0x26, 0x27, 0x28,
                    0x29, 0x2A, 0x2B, 0x2C,
                    0x2D, 0x2E, 0x2F, 0x30,
                    0x31, 0x32, 0x33, 0x34,
                    0x35, 0x36, 0x37, 0x38,
                    0x39, 0x3A, 0x3B, 0x3C,
                    0x3D, 0x3E, 0x3F, 0x40
            };
            key = new SecretKeySpec(keyBytes, "ChaCha20");
        }

        InputStream inputStream = new FileInputStream("config.properties");
        if (inputStream == null) {
            System.err.println("Configuration file not found!");
            System.exit(1);
        }

        Properties properties = new Properties();
        properties.load(inputStream);

        String remote = properties.getProperty("remote");
        String destinations = properties.getProperty("localdelivery");

        SocketAddress inSocketAddress = parseSocketAddress(remote);
        Set<SocketAddress> outSocketAddressSet = Arrays.stream(destinations.split(","))
                .map(s -> parseSocketAddress(s))
                .collect(Collectors.toSet());

        DatagramSocket inSocket = new DatagramSocket(inSocketAddress);
        DatagramSocket outSocket = new DatagramSocket();

        byte[] buffer = new byte[4 * 1024 + 64];

        while (true) {
            DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
            inSocket.receive(inPacket); // if remote is unicast

            byte[] encryptedData = Arrays.copyOfRange(inPacket.getData(), 0, inPacket.getLength());

            byte[] plaintext;
            try {
                if (algorithm.equals("AES")) {
                    plaintext = decryptGCM(encryptedData, key);
                } else {
                    plaintext = decryptChaCha(encryptedData, key);
                }
            } catch (Exception e) {
                System.out.print("X");
                continue;
            }

            System.out.print(".");

            for (SocketAddress outSocketAddress : outSocketAddressSet) {
                outSocket.send(new DatagramPacket(plaintext, plaintext.length, outSocketAddress));
            }
        }
    }

    private static InetSocketAddress parseSocketAddress(String socketAddress) {
        String[] split = socketAddress.split(":");
        String host = split[0];
        int port = Integer.parseInt(split[1]);
        return new InetSocketAddress(host, port);
    }

    public static byte[] decryptGCM(byte[] encryptedData, SecretKey key) throws Exception {

        byte[] nonce = Arrays.copyOfRange(encryptedData, 0, NONCE_LENGTH);
        byte[] ciphertext = Arrays.copyOfRange(encryptedData, NONCE_LENGTH, encryptedData.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        return cipher.doFinal(ciphertext);
    }

    public static byte[] decryptChaCha(byte[] encryptedData, Key key) throws Exception {

        byte[] nonce = Arrays.copyOfRange(encryptedData, 0, NONCE_LENGTH);
        byte[] ciphertext = Arrays.copyOfRange(encryptedData, NONCE_LENGTH, encryptedData.length);

        Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
        IvParameterSpec iv = new IvParameterSpec(nonce);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        return cipher.doFinal(ciphertext);
    }
}