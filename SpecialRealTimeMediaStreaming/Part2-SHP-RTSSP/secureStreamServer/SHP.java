import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class SHP {

    public static final String SHP_CLIENT_HELLO = "SHP_CLIENT_HELLO";
    public static final String SHP_SERVER_HELLO = "SHP_SERVER_HELLO";
    public static final String SHP_CLIENT_FINAL = "SHP_CLIENT_FINAL";

    private static final int NONCE_SIZE = 32;

    // ------------------------------------------------------------
    // ECDH KEY PAIR GENERATION
    // ------------------------------------------------------------

    public static KeyPair generateECDHKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        keyPairGenerator.initialize(ecSpec);
        return keyPairGenerator.generateKeyPair();
    }

    // ------------------------------------------------------------
    // NONCES
    // ------------------------------------------------------------

    public static byte[] generateNonce() {
        byte[] nonce = new byte[NONCE_SIZE];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    // ------------------------------------------------------------
    // PUBLIC KEY ENCODING / DECODING
    // ------------------------------------------------------------

    public static String publicKeyToBase64(PublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    public static PublicKey base64ToPublicKey(String encodedKey) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(encodedKey);

        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);

        return keyFactory.generatePublic(keySpec);
    }

    // ------------------------------------------------------------
    // ECDH SHARED SECRET
    // ------------------------------------------------------------

    public static byte[] computeSharedSecret(PrivateKey privateKey, PublicKey peerPublicKey) throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");

        keyAgreement.init(privateKey);
        keyAgreement.doPhase(peerPublicKey, true);

        return keyAgreement.generateSecret();
    }

    // ------------------------------------------------------------
    // KEY DERIVATION
    // ------------------------------------------------------------

    public static SecretKey deriveEncryptionKey(
            byte[] sharedSecret,
            byte[] clientNonce,
            byte[] serverNonce,
            String cipherSuite) throws Exception {

        byte[] keyMaterial = deriveKeyMaterial(
                sharedSecret,
                clientNonce,
                serverNonce,
                "RTSSP ENCRYPTION KEY");

        if (cipherSuite.equalsIgnoreCase("AES/GCM/NoPadding")
                || cipherSuite.equalsIgnoreCase("AES/CTR/NoPadding")
                || cipherSuite.equalsIgnoreCase("AES/CBC/PKCS5Padding")) {

            byte[] aesKey = Arrays.copyOf(keyMaterial, 32); // 256-bit AES
            return new SecretKeySpec(aesKey, "AES");
        }

        else if (cipherSuite.equalsIgnoreCase("ChaCha20-Poly1305")) {
            byte[] chachaKey = Arrays.copyOf(keyMaterial, 32); // 256-bit ChaCha20
            return new SecretKeySpec(chachaKey, "ChaCha20");
        }

        else {
            throw new RuntimeException("Unsupported ciphersuite: " + cipherSuite);
        }
    }

    public static SecretKey deriveMacKey(
            byte[] sharedSecret,
            byte[] clientNonce,
            byte[] serverNonce) throws Exception {

        byte[] keyMaterial = deriveKeyMaterial(
                sharedSecret,
                clientNonce,
                serverNonce,
                "RTSSP MAC KEY");

        byte[] macKey = Arrays.copyOf(keyMaterial, 32);
        return new SecretKeySpec(macKey, "HmacSHA256");
    }

    private static byte[] deriveKeyMaterial(
            byte[] sharedSecret,
            byte[] clientNonce,
            byte[] serverNonce,
            String label) throws Exception {

        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        digest.update(sharedSecret);
        digest.update(clientNonce);
        digest.update(serverNonce);
        digest.update(label.getBytes());

        return digest.digest();
    }

    // ------------------------------------------------------------
    // CIPHERSUITE NEGOTIATION
    // ------------------------------------------------------------

    public static String chooseCipherSuite(String[] clientSuites, String[] serverSuites) {
        for (String clientSuite : clientSuites) {
            for (String serverSuite : serverSuites) {
                if (clientSuite.trim().equalsIgnoreCase(serverSuite.trim())) {
                    return serverSuite.trim();
                }
            }
        }

        throw new RuntimeException("No common ciphersuite found");
    }

    public static boolean needsMacKey(String cipherSuite) {
        return cipherSuite.equalsIgnoreCase("AES/CTR/NoPadding")
                || cipherSuite.equalsIgnoreCase("AES/CBC/PKCS5Padding");
    }

    // ------------------------------------------------------------
    // MESSAGE CREATION
    // ------------------------------------------------------------

    public static String createClientHello(
            String movieName,
            String[] supportedCipherSuites,
            PublicKey clientECDHPublicKey,
            byte[] clientNonce) {
        return SHP_CLIENT_HELLO + "|" +
                movieName + "|" +
                String.join(",", supportedCipherSuites) + "|" +
                publicKeyToBase64(clientECDHPublicKey) + "|" +
                Base64.getEncoder().encodeToString(clientNonce);
    }

    public static String createServerHello(
            String movieName,
            String selectedCipherSuite,
            PublicKey serverECDHPublicKey,
            byte[] serverNonce,
            byte[] clientNonceResponse) {
        return SHP_SERVER_HELLO + "|" +
                movieName + "|" +
                selectedCipherSuite + "|" +
                publicKeyToBase64(serverECDHPublicKey) + "|" +
                Base64.getEncoder().encodeToString(serverNonce) + "|" +
                Base64.getEncoder().encodeToString(clientNonceResponse);
    }

    public static String createClientFinal(byte[] serverNonceResponse) {
        return SHP_CLIENT_FINAL + "|" +
                Base64.getEncoder().encodeToString(serverNonceResponse) + "|" +
                "START_STREAM";
    }

    // ------------------------------------------------------------
    // SIMPLE NONCE RESPONSE
    // ------------------------------------------------------------

    public static byte[] createNonceResponse(byte[] nonce) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(nonce);
        digest.update("SHP NONCE RESPONSE".getBytes());
        return digest.digest();
    }

    public static boolean verifyNonceResponse(byte[] nonce, byte[] response) throws Exception {
        byte[] expected = createNonceResponse(nonce);
        return Arrays.equals(expected, response);
    }

    // ------------------------------------------------------------
    // MESSAGE PARSING HELPERS
    // ------------------------------------------------------------

    public static String[] splitMessage(String message) {
        return message.split("\\|");
    }

    public static byte[] base64ToBytes(String value) {
        return Base64.getDecoder().decode(value);
    }
}