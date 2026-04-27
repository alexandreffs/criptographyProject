/*
* secureStreamServer.java 
* Streaming server: streams video frames in UDP packets
* for clients to play in real time the transmitted movies
*/

import java.io.*;
import java.net.*;
import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class secureStreamServer {

	private static final int NONCE_LENGTH = 12;
	private static final int GCM_TAG_LENGTH = 128;
	private static final SecureRandom random = new SecureRandom();

	static public void main(String[] args) throws Exception {

		if (args.length != 4) {
			System.out.println("Erro, usar: java secureStreamServer movies/cars.dat localhost 8888 <encrypt-scheme>");
			System.exit(-1);
		}

		String algorithm = args[3]; // usar "AES" ou "CHACHA"

		// Shared key between server and proxy
		// The same bytes must be used in the proxy
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

		int size;
		int csize = 0;
		int count = 0;
		long time;
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

			byte[] encryptedFrame;
			if (algorithm.equals("AES")) {
				encryptedFrame = encryptGCM(frame, key);
			} else {
				encryptedFrame = encryptChaCha(frame, key);
			}

			DatagramPacket p = new DatagramPacket(encryptedFrame, encryptedFrame.length, addr);

			long t = System.nanoTime();

			// Decision about the right time to transmit
			Thread.sleep(Math.max(0, ((time - q0) - (t - t0)) / 1000000));

			// send datagram (udp packet) w/ payload frame
			// Frames sent encrypted

			s.send(p);

			// Just for awareness ... (debug)

			System.out.print(":");
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

	public static byte[] encryptGCM(byte[] plaintext, SecretKey key) throws Exception {

		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		byte[] nonce = new byte[NONCE_LENGTH];
		random.nextBytes(nonce);

		GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
		cipher.init(Cipher.ENCRYPT_MODE, key, spec);

		byte[] ciphertext = cipher.doFinal(plaintext);

		byte[] result = new byte[nonce.length + ciphertext.length];
		System.arraycopy(nonce, 0, result, 0, nonce.length);
		System.arraycopy(ciphertext, 0, result, nonce.length, ciphertext.length);
		return result;

	}

	public static byte[] encryptChaCha(byte[] plaintext, Key key) throws Exception {

		Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
		byte[] nonce = new byte[NONCE_LENGTH];
		random.nextBytes(nonce);

		IvParameterSpec iv = new IvParameterSpec(nonce);
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);

		byte[] ciphertext = cipher.doFinal(plaintext);

		byte[] result = new byte[nonce.length + ciphertext.length];
		System.arraycopy(nonce, 0, result, 0, nonce.length);
		System.arraycopy(ciphertext, 0, result, nonce.length, ciphertext.length);
		return result;

	}
}
