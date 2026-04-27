/*
* prgStreamServer.java 
* Streaming server: streams video frames in UDP packets
* for clients to play in real time the transmitted movies
*/

import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class prgStreamServer {

    private static final int SESSION_NONCE_LENGTH = 12;
    private static final SecureRandom random = new SecureRandom();

    static public void main(String[] args) throws Exception {

        // Shared key between server and proxy
        // The same bytes must be used in the proxy
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

        // One session nonce for the whole streaming session
        // identifies the streaming session
        byte[] sessionNonce = new byte[SESSION_NONCE_LENGTH];
        random.nextBytes(sessionNonce);

        if (args.length != 3) {
            System.out.println("Erro, usar: mySend <movie> <ip-multicast-address> <port>");
            System.out.println("        or: mySend <movie> <ip-unicast-address> <port>");
            System.exit(-1);
        }

        int size;
        int csize = 0;
        int count = 0;
        long time;
        int frameIndex = 0;

        DataInputStream g = new DataInputStream(new FileInputStream(args[0]));
        byte[] buff = new byte[4096];

        DatagramSocket s = new DatagramSocket();
        InetSocketAddress addr = new InetSocketAddress(args[1], Integer.parseInt(args[2]));
        long t0 = System.nanoTime(); // Ref. time
        long q0 = 0;

        // Movies are encoded in .dat files, where each
        // frame is encoded in a real-time sequence of MP4 frames
        // Somewhat an FFMPEG4 playing scheme

        // Each frame has:
        // Short size || Long Timestamp || byte[] EncodedMP4Frame
        // You can read (frame by frame to transmit ...
        // But you must folow the "real-time" encoding conditions

        while (g.available() > 0) {

            size = g.readShort(); // size of the frame
            csize = csize + size;
            time = g.readLong(); // timestamp of the frame
            if (count == 0)
                q0 = time; // ref. time in the stream
            count += 1;

            g.readFully(buff, 0, size);

            // Copy only the valid frame bytes
            byte[] frame = new byte[size];
            System.arraycopy(buff, 0, frame, 0, size);

            // Generate a reproducible keystream for this specific frame
            byte[] keystream = generateKeystream(prgKey, sessionNonce, frameIndex, size);

            // Encrypt frame with XOR
            // for each byte -> ciphertext[i] = plaintext[i] XOR keystream[i]
            byte[] ciphertext = xorBytes(frame, keystream);

            // [sessionNonce(12)][frameIndex(4)][length(4)][ciphertext(length)]
            ByteBuffer packetBuffer = ByteBuffer.allocate(SESSION_NONCE_LENGTH + 4 + 4 + ciphertext.length);
            packetBuffer.put(sessionNonce);
            packetBuffer.putInt(frameIndex);
            packetBuffer.putInt(size);
            packetBuffer.put(ciphertext);

            byte[] packetData = packetBuffer.array();
            DatagramPacket p = new DatagramPacket(packetData, packetData.length, addr);

            long t = System.nanoTime(); // what time is it?

            // Decision about the right time to transmit
            Thread.sleep(Math.max(0, ((time - q0) - (t - t0)) / 1000000));

            // send datagram (udp packet) w/ payload frame)
            // Frames sent encrypted with DPRG + XOR

            s.send(p);

            // Just for awareness ... (debug)

            System.out.print(":");

            frameIndex++;
        }

        long tend = System.nanoTime(); // "The end" time
        System.out.println();
        System.out.println("DONE! all frames sent: " + count);

        long duration = (tend - t0) / 1000000000;
        if (duration > 0) {
            System.out.println("Movie duration " + duration + " s");
            System.out.println("Throughput " + count / duration + " fps");
            System.out.println("Throughput " + (8 * (csize) / duration) / 1000 + " Kbps");
        } else {
            System.out.println("Movie duration < 1 s");
        }
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

            // HMAC(key, sessionNonce || frameIndex || blockCounter)
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
