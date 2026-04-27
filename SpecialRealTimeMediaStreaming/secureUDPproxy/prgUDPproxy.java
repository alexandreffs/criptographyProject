/* prgUDPproxy,
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

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class prgUDPproxy {

    private static final int SESSION_NONCE_LENGTH = 12;

    public static void main(String[] args) throws Exception {

        // Shared key between server and proxy
        // The same bytes must be used in the server
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
        SecretKeySpec prgKey = new SecretKeySpec(keyBytes, "HmacSHA256");

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

            byte[] packetData = Arrays.copyOfRange(inPacket.getData(), 0, inPacket.getLength());

            try {
                ByteBuffer packetBuffer = ByteBuffer.wrap(packetData);

                byte[] sessionNonce = new byte[SESSION_NONCE_LENGTH];
                packetBuffer.get(sessionNonce);

                int frameIndex = packetBuffer.getInt();
                int length = packetBuffer.getInt();

                byte[] ciphertext = new byte[length];
                packetBuffer.get(ciphertext);

                // Regenerate the exact same keystream
                byte[] keystream = generateKeystream(prgKey, sessionNonce, frameIndex, length);

                // Decrypt with XOR -> plaintext = ciphertext XOR keystream
                byte[] plaintext = xorBytes(ciphertext, keystream);

                System.out.print(".");

                for (SocketAddress outSocketAddress : outSocketAddressSet) {
                    outSocket.send(new DatagramPacket(plaintext, plaintext.length, outSocketAddress));
                }

            } catch (Exception e) {
                System.out.print("X");
            }
        }
    }

    private static InetSocketAddress parseSocketAddress(String socketAddress) {
        String[] split = socketAddress.split(":");
        String host = split[0];
        int port = Integer.parseInt(split[1]);
        return new InetSocketAddress(host, port);
    }

    public static byte[] generateKeystream(SecretKeySpec key, byte[] sessionNonce, int frameIndex, int length)
            throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        int blockCounter = 0;

        while (output.size() < length) {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);

            ByteBuffer input = ByteBuffer.allocate(sessionNonce.length + 4 + 4);
            input.put(sessionNonce);
            input.putInt(frameIndex);
            input.putInt(blockCounter);

            byte[] block = mac.doFinal(input.array());
            output.write(block);

            blockCounter++;
        }

        byte[] stream = output.toByteArray();
        byte[] keystream = new byte[length];
        System.arraycopy(stream, 0, keystream, 0, length);
        return keystream;
    }

    public static byte[] xorBytes(byte[] a, byte[] b) {
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }
}
