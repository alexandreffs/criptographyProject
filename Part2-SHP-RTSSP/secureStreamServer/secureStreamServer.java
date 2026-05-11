import common.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.X509Certificate;

public class secureStreamServer {

	private static final String SERVER_KEYSTORE = "secureStreamServer/server-keystore.jks";
	private static final String SERVER_TRUSTSTORE = "secureStreamServer/server-truststore.jks";
	private static final String PASSWORD = "password";
	private static final String SERVER_ALIAS = "server";
	private static final String PROXY_ALIAS = "proxy";

	public static void main(String[] args) throws Exception {

		if (args.length != 1) {
			System.out.println("Use: java -cp .;secureStreamServer secureStreamServer 9999");
			System.exit(-1);
		}

		int controlPort = Integer.parseInt(args[0]);

		String[] serverSupportedCipherSuites = {
				"AES/GCM/NoPadding",
				"ChaCha20-Poly1305",
				"AES/CTR/NoPadding"
		};

		PrivateKey serverPrivateKey = CertificateUtils.loadPrivateKey(
				SERVER_KEYSTORE,
				PASSWORD,
				SERVER_ALIAS,
				PASSWORD);

		X509Certificate serverCertificate = CertificateUtils.loadCertificateFromKeystore(
				SERVER_KEYSTORE,
				PASSWORD,
				SERVER_ALIAS);

		X509Certificate trustedProxyCertificate = CertificateUtils.loadTrustedCertificate(
				SERVER_TRUSTSTORE,
				PASSWORD,
				PROXY_ALIAS);

		DatagramSocket controlSocket = new DatagramSocket(controlPort);

		System.out.println("Server waiting for signed SHP CLIENT_HELLO on port " + controlPort);

		try {
			byte[] requestBuffer = new byte[16384];

			DatagramPacket requestPacket = new DatagramPacket(requestBuffer, requestBuffer.length);

			controlSocket.receive(requestPacket);

			String clientHello = new String(
					requestPacket.getData(),
					0,
					requestPacket.getLength());

			System.out.println("SHP CLIENT_HELLO received");

			String[] clientParts = SHP.splitMessage(clientHello);

			if (!clientParts[0].equals(SHP.SHP_CLIENT_HELLO)) {
				sendPlainError(controlSocket, requestPacket.getSocketAddress(),
						"Invalid SHP CLIENT_HELLO");
				return;
			}

			if (!SHP.verifyClientHelloSignature(clientParts)) {
				sendPlainError(controlSocket, requestPacket.getSocketAddress(),
						"Invalid CLIENT_HELLO signature");
				return;
			}

			X509Certificate receivedProxyCertificate = SHP.base64ToCertificate(clientParts[6]);

			CertificateUtils.verifyCertificateIsTrusted(
					receivedProxyCertificate,
					trustedProxyCertificate);

			String movieName = clientParts[1];
			String proxyStreamEndpoint = clientParts[2];
			String[] clientSupportedCipherSuites = clientParts[3].split(",");
			PublicKey clientECDHPublicKey = SHP.base64ToPublicKey(clientParts[4]);
			byte[] clientNonce = SHP.base64ToBytes(clientParts[5]);

			String movieFile = "secureStreamServer/movies/" + movieName;

			File movieDiskFile = new File(movieFile);

			if (!movieDiskFile.exists()) {
				sendPlainError(controlSocket, requestPacket.getSocketAddress(),
						"Movie does not exist: " + movieName);
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
					clientNonceResponse,
					serverCertificate,
					serverPrivateKey);

			byte[] serverHelloBytes = serverHello.getBytes();

			controlSocket.send(new DatagramPacket(
					serverHelloBytes,
					serverHelloBytes.length,
					requestPacket.getSocketAddress()));

			System.out.println("Proxy certificate trusted");
			System.out.println("CLIENT_HELLO signature verified");
			System.out.println("SHP SERVER_HELLO sent and signed");
			System.out.println("Selected CipherSuite: " + selectedCipherSuite);
			System.out.println("Session keys derived");

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
			System.out.println("SHP handshake completed with mutual authentication");
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
			System.out.println("SHP/RTSSP error: " + e.getMessage());
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

		String error = SHP.SHP_ERROR + "|" + message;
		byte[] data = error.getBytes();

		socket.send(new DatagramPacket(data, data.length, address));
	}

	private static InetSocketAddress parseSocketAddress(String socketAddress) {
		String[] split = socketAddress.split(":");
		return new InetSocketAddress(split[0], Integer.parseInt(split[1]));
	}
}
