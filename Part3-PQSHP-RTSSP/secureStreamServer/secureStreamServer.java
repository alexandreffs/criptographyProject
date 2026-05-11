import common.*;

import java.io.*;
import java.net.*;
import java.security.*;

public class secureStreamServer {

	public static void main(String[] args) throws Exception {

		if (args.length != 1) {
			System.out.println(
					"Use: java -cp \".;bcprov-jdk18on-1.84.jar;secureStreamServer\" secureStreamServer 9999");
			System.exit(-1);
		}

		int controlPort = Integer.parseInt(args[0]);

		String[] serverSupportedCipherSuites = {
				"AES/GCM/NoPadding",
				"ChaCha20-Poly1305",
				"AES/CTR/NoPadding"
		};

		DatagramSocket controlSocket = new DatagramSocket(controlPort);

		System.out.println("Server waiting for signed PQ-SHP CLIENT_HELLO on port " + controlPort);

		try {
			/*
			 * ============================================================
			 * 1. RECEIVE PQ-SHP CLIENT_HELLO
			 * ============================================================
			 */

			byte[] requestBuffer = new byte[65507];
			DatagramPacket requestPacket = new DatagramPacket(requestBuffer, requestBuffer.length);

			controlSocket.receive(requestPacket);

			String clientHello = new String(
					requestPacket.getData(),
					0,
					requestPacket.getLength());

			System.out.println("PQ-SHP CLIENT_HELLO received");

			String[] clientParts = PQSHP.splitMessage(clientHello);

			if (!clientParts[0].equals(PQSHP.PQ_CLIENT_HELLO)) {
				sendPlainError(controlSocket, requestPacket.getSocketAddress(),
						"Invalid PQ-SHP CLIENT_HELLO");
				return;
			}

			if (!PQSHP.verifyClientHelloSignature(clientParts)) {
				sendPlainError(controlSocket, requestPacket.getSocketAddress(),
						"Invalid PQ-SHP CLIENT_HELLO Dilithium signature");
				return;
			}

			System.out.println("PQ-SHP CLIENT_HELLO Dilithium signature verified");

			String movieName = clientParts[1];
			String proxyStreamEndpoint = clientParts[2];
			String[] clientSupportedCipherSuites = clientParts[3].split(",");
			PublicKey clientKyberPublicKey = PQSHP.base64ToKyberPublicKey(clientParts[4]);
			byte[] clientNonce = PQSHP.base64ToBytes(clientParts[5]);

			/*
			 * ============================================================
			 * 2. VALIDATE MOVIE
			 * ============================================================
			 */

			String movieFile = "secureStreamServer/movies/" + movieName;
			File movieDiskFile = new File(movieFile);

			if (!movieDiskFile.exists()) {
				sendPlainError(controlSocket, requestPacket.getSocketAddress(),
						"Movie does not exist: " + movieName);
				return;
			}

			/*
			 * ============================================================
			 * 3. CHOOSE CIPHERSUITE
			 * ============================================================
			 */

			String selectedCipherSuite = PQSHP.chooseCipherSuite(
					clientSupportedCipherSuites,
					serverSupportedCipherSuites);

			/*
			 * ============================================================
			 * 4. KYBER ENCAPSULATION
			 * ============================================================
			 */

			PQSHP.KEMResult kemResult = PQSHP.kyberEncapsulate(clientKyberPublicKey);

			byte[] kyberSharedSecret = kemResult.sharedSecret;
			byte[] kyberEncapsulation = kemResult.encapsulation;

			/*
			 * ============================================================
			 * 5. SERVER DILITHIUM KEYPAIR
			 * ============================================================
			 */

			KeyPair serverDilithiumKeyPair = PQSHP.generateDilithiumKeyPair();

			/*
			 * ============================================================
			 * 6. DERIVE RTSSP SESSION KEYS
			 * ============================================================
			 */

			byte[] serverNonce = PQSHP.generateNonce();

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

			CryptoConfig crypto = pqContext.toCryptoConfig();

			/*
			 * ============================================================
			 * 7. SEND SIGNED PQ-SHP SERVER_HELLO
			 * ============================================================
			 */

			byte[] clientNonceResponse = PQSHP.createNonceResponse(clientNonce);

			String serverHello = PQSHP.createServerHello(
					movieName,
					selectedCipherSuite,
					serverNonce,
					kyberEncapsulation,
					serverDilithiumKeyPair.getPublic(),
					clientNonceResponse,
					serverDilithiumKeyPair.getPrivate());

			byte[] serverHelloBytes = serverHello.getBytes();

			controlSocket.send(new DatagramPacket(
					serverHelloBytes,
					serverHelloBytes.length,
					requestPacket.getSocketAddress()));

			System.out.println("PQ-SHP SERVER_HELLO sent and signed");
			System.out.println("Selected CipherSuite: " + selectedCipherSuite);
			System.out.println("Kyber shared secret established");
			System.out.println("RTSSP session keys derived");

			/*
			 * ============================================================
			 * 8. RECEIVE ENCRYPTED PQ-SHP CLIENT_FINAL
			 * ============================================================
			 */

			byte[] finalBuffer = new byte[65507];
			DatagramPacket finalPacket = new DatagramPacket(finalBuffer, finalBuffer.length);

			controlSocket.receive(finalPacket);

			byte[] protectedClientFinal = new byte[finalPacket.getLength()];

			System.arraycopy(
					finalPacket.getData(),
					0,
					protectedClientFinal,
					0,
					finalPacket.getLength());

			RTSSP.Packet clientFinalPacket = RTSSP.unprotect(protectedClientFinal, crypto);

			String clientFinal = new String(clientFinalPacket.payload);

			String[] finalParts = PQSHP.splitMessage(clientFinal);

			if (!finalParts[0].equals(PQSHP.PQ_CLIENT_FINAL)) {
				throw new SecurityException("Invalid PQ-SHP CLIENT_FINAL");
			}

			byte[] serverNonceResponse = PQSHP.base64ToBytes(finalParts[1]);
			String command = finalParts[2];

			if (!PQSHP.verifyNonceResponse(serverNonce, serverNonceResponse)) {
				throw new SecurityException("Invalid response to server nonce");
			}

			if (!command.equals("START_STREAM")) {
				throw new SecurityException("Invalid PQ-SHP final command");
			}

			System.out.println("PQ-SHP CLIENT_FINAL received and verified");
			System.out.println("PQ-SHP handshake completed");
			System.out.println("Starting RTSSP stream...");

			InetSocketAddress proxyStreamAddress = parseSocketAddress(proxyStreamEndpoint);

			streamMovie(
					movieFile,
					movieName,
					proxyStreamAddress.getHostString(),
					proxyStreamAddress.getPort(),
					crypto);
		}

		catch (Exception e) {
			System.out.println("PQ-SHP/RTSSP error: " + e.getMessage());
			e.printStackTrace();
		}

		finally {
			controlSocket.close();
		}
	}

	private static void streamMovie(
			String movieFile,
			String movieName,
			String proxyHost,
			int proxyPort,
			CryptoConfig crypto) throws Exception {

		DatagramSocket socket = new DatagramSocket();
		InetSocketAddress addr = new InetSocketAddress(proxyHost, proxyPort);

		DataInputStream movie = new DataInputStream(new FileInputStream(movieFile));
		byte[] buff = new byte[4096];

		int seq = 1;
		int count = 0;
		int csize = 0;

		long t0 = System.nanoTime();
		long q0 = 0;

		byte[] startPayload = ("START:" + movieName).getBytes();

		byte[] startPacket = RTSSP.protect(
				RTSSP.TYPE_START,
				seq++,
				startPayload,
				crypto);

		socket.send(new DatagramPacket(startPacket, startPacket.length, addr));

		System.out.println("RTSSP START sent");

		while (movie.available() > 0) {

			int size = movie.readShort();
			long timestamp = movie.readLong();

			if (count == 0) {
				q0 = timestamp;
			}

			movie.readFully(buff, 0, size);

			byte[] frame = new byte[size];
			System.arraycopy(buff, 0, frame, 0, size);

			byte[] protectedFrame = RTSSP.protect(
					RTSSP.TYPE_DATA,
					seq++,
					frame,
					crypto);

			long now = System.nanoTime();

			Thread.sleep(Math.max(
					0,
					((timestamp - q0) - (now - t0)) / 1000000));

			socket.send(new DatagramPacket(
					protectedFrame,
					protectedFrame.length,
					addr));

			count++;
			csize += size;

			System.out.print(":");
		}

		byte[] endPayload = ("END:" + count).getBytes();

		byte[] endPacket = RTSSP.protect(
				RTSSP.TYPE_END,
				seq++,
				endPayload,
				crypto);

		socket.send(new DatagramPacket(endPacket, endPacket.length, addr));

		long tend = System.nanoTime();
		long duration = (tend - t0) / 1000000000;

		System.out.println();
		System.out.println("RTSSP END sent");
		System.out.println("DONE! Frames sent: " + count);

		if (duration > 0) {
			System.out.println("Movie duration: " + duration + " s");
			System.out.println("Throughput: " + count / duration + " fps");
			System.out.println("Throughput: " + (8 * csize / duration) / 1000 + " Kbps");
		}

		movie.close();
		socket.close();
	}

	private static void sendPlainError(
			DatagramSocket socket,
			SocketAddress address,
			String message) throws Exception {

		String error = PQSHP.PQ_ERROR + "|" + message;
		byte[] data = error.getBytes();

		socket.send(new DatagramPacket(data, data.length, address));
	}

	private static InetSocketAddress parseSocketAddress(String socketAddress) {
		String[] split = socketAddress.split(":");
		return new InetSocketAddress(split[0], Integer.parseInt(split[1]));
	}
}
