import common.*;
import java.io.*;
import java.net.*;
import java.util.Map;

public class secureStreamServer {

	public static void main(String[] args) throws Exception {

		if (args.length != 1) {
			System.out.println("Use: java secureStreamServer 9999");
			System.exit(-1);
		}

		int controlPort = Integer.parseInt(args[0]);

		DatagramSocket controlSocket = new DatagramSocket(controlPort);

		System.out.println("Server waiting for movie request on port " + controlPort);

		byte[] requestBuffer = new byte[1024];
		DatagramPacket requestPacket = new DatagramPacket(requestBuffer, requestBuffer.length);

		controlSocket.receive(requestPacket);

		String request = new String(
				requestPacket.getData(),
				0,
				requestPacket.getLength());

		System.out.println("Request received: " + request);

		if (!request.startsWith("REQUEST:")) {
			System.out.println("Invalid request");
			controlSocket.close();
			return;
		}

		String[] parts = request.split(":");

		String movieName = parts[1];
		String proxyHost = parts[2];
		int proxyPort = Integer.parseInt(parts[3]);

		String movieFile = "secureStreamServer/movies/" + movieName;

		File movieDiskFile = new File(movieFile);

		if (!movieDiskFile.exists()) {
			System.out.println("Movie does not exist: " + movieFile);
			controlSocket.close();
			return;
		}

		Map<String, CryptoConfig> configs = CryptoConfig.loadAll("Cryptoconfig.conf");
		CryptoConfig crypto = configs.get(movieName);

		if (crypto == null) {
			throw new RuntimeException("No crypto config found for movie: " + movieName);
		}

		System.out.println("Movie: " + movieName);
		System.out.println("CipherSuite: " + crypto.cipherSuite);

		DatagramSocket socket = new DatagramSocket();
		InetSocketAddress addr = new InetSocketAddress(proxyHost, proxyPort);

		DataInputStream movie = new DataInputStream(new FileInputStream(movieFile));
		byte[] buff = new byte[4096];

		int seq = 0;
		int count = 0;
		int csize = 0;

		long t0 = System.nanoTime();
		long q0 = 0;

		byte[] startPayload = ("START:" + movieName).getBytes();
		byte[] startPacket = RTSSP.protect(RTSSP.TYPE_START, seq++, startPayload, crypto);
		socket.send(new DatagramPacket(startPacket, startPacket.length, addr));

		System.out.println("START sent");

		while (movie.available() > 0) {

			int size = movie.readShort();
			long timestamp = movie.readLong();

			if (count == 0) {
				q0 = timestamp;
			}

			movie.readFully(buff, 0, size);

			byte[] frame = new byte[size];
			System.arraycopy(buff, 0, frame, 0, size);

			byte[] protectedFrame = RTSSP.protect(RTSSP.TYPE_DATA, seq++, frame, crypto);

			long now = System.nanoTime();
			Thread.sleep(Math.max(0, ((timestamp - q0) - (now - t0)) / 1000000));

			socket.send(new DatagramPacket(protectedFrame, protectedFrame.length, addr));

			count++;
			csize += size;

			System.out.print(":");
		}

		byte[] endPayload = ("END:" + count).getBytes();
		byte[] endPacket = RTSSP.protect(RTSSP.TYPE_END, seq++, endPayload, crypto);
		socket.send(new DatagramPacket(endPacket, endPacket.length, addr));

		long tend = System.nanoTime();
		long duration = (tend - t0) / 1000000000;

		System.out.println();
		System.out.println("END sent");
		System.out.println("DONE! Frames sent: " + count);

		if (duration > 0) {
			System.out.println("Movie duration: " + duration + " s");
			System.out.println("Throughput: " + count / duration + " fps");
			System.out.println("Throughput: " + (8 * csize / duration) / 1000 + " Kbps");
		}

		movie.close();
		socket.close();
		controlSocket.close();
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