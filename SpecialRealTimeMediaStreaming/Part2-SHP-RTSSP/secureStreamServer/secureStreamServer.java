import java.io.*;
import java.net.*;
import java.security.*;

public class secureStreamServer {

	public static void main(String[] args) throws Exception {

		if (args.length != 1) {
			System.out.println("Use: java secureStreamServer 9999");
			System.exit(-1);
		}

		int controlPort = Integer.parseInt(args[0]);

		String[] serverSupportedCipherSuites = {
				"AES/GCM/NoPadding",
				"ChaCha20-Poly1305",
				"AES/CTR/NoPadding"
		};

		DatagramSocket controlSocket = new DatagramSocket(controlPort);

		System.out.println("Server waiting for SHP CLIENT_HELLO on port " + controlPort);

		byte[] requestBuffer = new byte[8192];
		DatagramPacket requestPacket = new DatagramPacket(requestBuffer, requestBuffer.length);

		controlSocket.receive(requestPacket);

		String clientHello = new String(
				requestPacket.getData(),
				0,
				requestPacket.getLength());

		System.out.println("Received: " + clientHello);

		String[] clientParts = SHP.splitMessage(clientHello);

		if (!clientParts[0].equals(SHP.SHP_CLIENT_HELLO)) {
			sendPlainError(controlSocket, requestPacket.getSocketAddress(),
					"Invalid SHP CLIENT_HELLO");
			controlSocket.close();
			return;
		}

		String movieName = clientParts[1];
		String[] clientSupportedCipherSuites = clientParts[2].split(",");
		PublicKey clientECDHPublicKey = SHP.base64ToPublicKey(clientParts[3]);
		byte[] clientNonce = SHP.base64ToBytes(clientParts[4]);

		String movieFile = "secureStreamServer/movies/" + movieName;

		File movieDiskFile = new File(movieFile);

		if (!movieDiskFile.exists()) {
			sendPlainError(controlSocket, requestPacket.getSocketAddress(),
					"Movie does not exist: " + movieName);
			controlSocket.close();
			return;
		}

		String selectedCipherSuite = SHP.chooseCipherSuite(
				clientSupportedCipherSuites,
				serverSupportedCipherSuites);

		KeyPair serverECDHKeyPair = SHP.generateECDHKeyPair();
		byte[] serverNonce = SHP.generateNonce();

		byte[] sharedSecret = SHP.computeSharedSecret(
				serverECDHKeyPair.getPrivate(),
				clientECDHPublicKey);

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

		CryptoConfig crypto = shpContext.toCryptoConfig();

		byte[] clientNonceResponse = SHP.createNonceResponse(clientNonce);

		String serverHello = SHP.createServerHello(
				movieName,
				selectedCipherSuite,
				serverECDHKeyPair.getPublic(),
				serverNonce,
				clientNonceResponse);

		byte[] serverHelloBytes = serverHello.getBytes();

		controlSocket.send(new DatagramPacket(
				serverHelloBytes,
				serverHelloBytes.length,
				requestPacket.getSocketAddress()));

		System.out.println("SHP SERVER_HELLO sent");
		System.out.println("Selected CipherSuite: " + selectedCipherSuite);
		System.out.println("Session keys derived");

		/*
		 * Receive encrypted CLIENT_FINAL
		 */

		byte[] finalBuffer = new byte[8192];
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

		String[] finalParts = SHP.splitMessage(clientFinal);

		if (!finalParts[0].equals(SHP.SHP_CLIENT_FINAL)) {
			throw new SecurityException("Invalid SHP CLIENT_FINAL");
		}

		byte[] serverNonceResponse = SHP.base64ToBytes(finalParts[1]);
		String command = finalParts[2];

		if (!SHP.verifyNonceResponse(serverNonce, serverNonceResponse)) {
			throw new SecurityException("Invalid response to server nonce");
		}

		if (!command.equals("START_STREAM")) {
			throw new SecurityException("Invalid SHP final command");
		}

		System.out.println("SHP CLIENT_FINAL received and verified");
		System.out.println("SHP handshake completed");
		System.out.println("Starting RTSSP stream...");

		/*
		 * Extract proxy RTSSP destination from CLIENT_HELLO sender information.
		 * For local tests, proxy receives stream on localhost:8888.
		 */

		String proxyHost = "localhost";
		int proxyPort = 8888;

		streamMovie(movieFile, movieName, proxyHost, proxyPort, crypto);

		controlSocket.close();
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

		String error = "SHP_ERROR|" + message;
		byte[] data = error.getBytes();

		socket.send(new DatagramPacket(data, data.length, address));
	}
}

// import java.io.*;
// import java.net.*;
// import java.util.Map;

// public class secureStreamServer {

// public static void main(String[] args) throws Exception {

// if (args.length != 3) {
// System.out.println("Use: java secureStreamServer.secureStreamServer
// movies/cars.dat localhost 8888");
// System.exit(-1);
// }

// String movieFile = args[0];
// String host = args[1];
// int port = Integer.parseInt(args[2]);

// String movieName = new File(movieFile).getName();

// Map<String, CryptoConfig> configs =
// CryptoConfig.loadAll("Cryptoconfig.conf");
// CryptoConfig crypto = configs.get(movieName);

// if (crypto == null) {
// throw new RuntimeException("No crypto config found for movie: " + movieName);
// }

// System.out.println("Movie: " + movieName);
// System.out.println("CipherSuite: " + crypto.cipherSuite);

// DatagramSocket socket = new DatagramSocket();
// InetSocketAddress addr = new InetSocketAddress(host, port);

// DataInputStream movie = new DataInputStream(new FileInputStream(movieFile));
// byte[] buff = new byte[4096];

// int seq = 0;
// int count = 0;
// int csize = 0;

// long t0 = System.nanoTime();
// long q0 = 0;

// byte[] startPayload = ("START:" + movieName).getBytes();
// byte[] startPacket = RTSSP.protect(RTSSP.TYPE_START, seq++, startPayload,
// crypto);
// socket.send(new DatagramPacket(startPacket, startPacket.length, addr));

// System.out.println("START sent");

// while (movie.available() > 0) {

// int size = movie.readShort();
// long timestamp = movie.readLong();

// if (count == 0) {
// q0 = timestamp;
// }

// movie.readFully(buff, 0, size);

// byte[] frame = new byte[size];
// System.arraycopy(buff, 0, frame, 0, size);

// byte[] protectedFrame = RTSSP.protect(RTSSP.TYPE_DATA, seq++, frame, crypto);

// long now = System.nanoTime();
// Thread.sleep(Math.max(0, ((timestamp - q0) - (now - t0)) / 1000000));

// DatagramPacket packet = new DatagramPacket(protectedFrame,
// protectedFrame.length, addr);
// socket.send(packet);

// count++;
// csize += size;

// System.out.print(":");
// }

// byte[] endPayload = ("END:" + count).getBytes();
// byte[] endPacket = RTSSP.protect(RTSSP.TYPE_END, seq++, endPayload, crypto);
// socket.send(new DatagramPacket(endPacket, endPacket.length, addr));

// long tend = System.nanoTime();
// long duration = (tend - t0) / 1000000000;

// System.out.println();
// System.out.println("END sent");
// System.out.println("DONE! Frames sent: " + count);

// if (duration > 0) {
// System.out.println("Movie duration: " + duration + " s");
// System.out.println("Throughput: " + count / duration + " fps");
// System.out.println("Throughput: " + (8 * csize / duration) / 1000 + " Kbps");
// }

// movie.close();
// socket.close();
// }
// }