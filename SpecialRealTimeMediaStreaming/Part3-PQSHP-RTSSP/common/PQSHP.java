package common;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;

public class PQSHP {

    public static final String PROVIDER = "BCPQC";

    public static final String KYBER_ALGORITHM = "Kyber";
    public static final String DILITHIUM_ALGORITHM = "Dilithium";

    public static final String PQ_CLIENT_HELLO = "PQ_SHP_CLIENT_HELLO";
    public static final String PQ_SERVER_HELLO = "PQ_SHP_SERVER_HELLO";
    public static final String PQ_CLIENT_FINAL = "PQ_SHP_CLIENT_FINAL";
    public static final String PQ_ERROR = "PQ_SHP_ERROR";

    private static final int NONCE_SIZE = 32;

    private static final KyberParameterSpec KYBER_SPEC = KyberParameterSpec.kyber768;
    private static final DilithiumParameterSpec DILITHIUM_SPEC = DilithiumParameterSpec.dilithium3;

    static {
        ensureProvider();
    }

    public static void ensureProvider() {
        if (Security.getProvider(PROVIDER) == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    // ============================================================
    // NONCES
    // ============================================================

    public static byte[] generateNonce() {
        byte[] nonce = new byte[NONCE_SIZE];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    public static byte[] createNonceResponse(byte[] nonce) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        digest.update(nonce);
        digest.update("PQ-SHP NONCE RESPONSE".getBytes());

        return digest.digest();
    }

    public static boolean verifyNonceResponse(byte[] nonce, byte[] response) throws Exception {
        return Arrays.equals(createNonceResponse(nonce), response);
    }

    // ============================================================
    // KYBER / CRYSTALS-KYBER KEM
    // ============================================================

    public static KeyPair generateKyberKeyPair() throws Exception {
        ensureProvider();

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KYBER_ALGORITHM, PROVIDER);

        keyPairGenerator.initialize(KYBER_SPEC, new SecureRandom());

        return keyPairGenerator.generateKeyPair();
    }

    public static KEMResult kyberEncapsulate(PublicKey receiverKyberPublicKey) throws Exception {
        ensureProvider();

        KeyGenerator keyGenerator = KeyGenerator.getInstance(KYBER_ALGORITHM, PROVIDER);

        /*
         * The generated secret key will be 256-bit AES-compatible key material.
         * We still feed it into our own KDF together with the nonces.
         */
        KEMGenerateSpec kemGenerateSpec = new KEMGenerateSpec(receiverKyberPublicKey, "AES", 256);

        keyGenerator.init(kemGenerateSpec, new SecureRandom());

        SecretKeyWithEncapsulation secretWithEncapsulation = (SecretKeyWithEncapsulation) keyGenerator.generateKey();

        return new KEMResult(
                secretWithEncapsulation.getEncoded(),
                secretWithEncapsulation.getEncapsulation());
    }

    public static byte[] kyberDecapsulate(
            PrivateKey receiverKyberPrivateKey,
            byte[] encapsulation) throws Exception {

        ensureProvider();

        KeyGenerator keyGenerator = KeyGenerator.getInstance(KYBER_ALGORITHM, PROVIDER);

        KEMExtractSpec kemExtractSpec = new KEMExtractSpec(receiverKyberPrivateKey, encapsulation, "AES", 256);

        keyGenerator.init(kemExtractSpec);

        SecretKeyWithEncapsulation extractedSecret = (SecretKeyWithEncapsulation) keyGenerator.generateKey();

        return extractedSecret.getEncoded();
    }

    public static class KEMResult {
        public byte[] sharedSecret;
        public byte[] encapsulation;

        public KEMResult(byte[] sharedSecret, byte[] encapsulation) {
            this.sharedSecret = sharedSecret;
            this.encapsulation = encapsulation;
        }
    }

    // ============================================================
    // DILITHIUM / CRYSTALS-DILITHIUM SIGNATURES
    // ============================================================

    public static KeyPair generateDilithiumKeyPair() throws Exception {
        ensureProvider();

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(DILITHIUM_ALGORITHM, PROVIDER);

        keyPairGenerator.initialize(DILITHIUM_SPEC, new SecureRandom());

        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] dilithiumSign(
            byte[] data,
            PrivateKey dilithiumPrivateKey) throws Exception {

        ensureProvider();

        Signature signature = Signature.getInstance(DILITHIUM_ALGORITHM, PROVIDER);

        signature.initSign(dilithiumPrivateKey, new SecureRandom());
        signature.update(data);

        return signature.sign();
    }

    public static boolean dilithiumVerify(
            byte[] data,
            byte[] receivedSignature,
            PublicKey dilithiumPublicKey) throws Exception {

        ensureProvider();

        Signature signature = Signature.getInstance(DILITHIUM_ALGORITHM, PROVIDER);

        signature.initVerify(dilithiumPublicKey);
        signature.update(data);

        return signature.verify(receivedSignature);
    }

    // ============================================================
    // PUBLIC KEY ENCODING / DECODING
    // ============================================================

    public static String publicKeyToBase64(PublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    public static PublicKey base64ToKyberPublicKey(String encodedKey) throws Exception {
        ensureProvider();

        byte[] keyBytes = Base64.getDecoder().decode(encodedKey);

        KeyFactory keyFactory = KeyFactory.getInstance(KYBER_ALGORITHM, PROVIDER);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);

        return keyFactory.generatePublic(keySpec);
    }

    public static PublicKey base64ToDilithiumPublicKey(String encodedKey) throws Exception {
        ensureProvider();

        byte[] keyBytes = Base64.getDecoder().decode(encodedKey);

        KeyFactory keyFactory = KeyFactory.getInstance(DILITHIUM_ALGORITHM, PROVIDER);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);

        return keyFactory.generatePublic(keySpec);
    }

    public static String bytesToBase64(byte[] value) {
        return Base64.getEncoder().encodeToString(value);
    }

    public static byte[] base64ToBytes(String value) {
        return Base64.getDecoder().decode(value);
    }

    // ============================================================
    // CIPHERSUITE NEGOTIATION
    // ============================================================

    public static String chooseCipherSuite(
            String[] clientSuites,
            String[] serverSuites) {

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

    // ============================================================
    // KEY DERIVATION FOR RTSSP
    // ============================================================

    public static SecretKey deriveEncryptionKey(
            byte[] kyberSharedSecret,
            byte[] clientNonce,
            byte[] serverNonce,
            String cipherSuite) throws Exception {

        byte[] keyMaterial = deriveKeyMaterial(
                kyberSharedSecret,
                clientNonce,
                serverNonce,
                "RTSSP PQ ENCRYPTION KEY");

        if (cipherSuite.equalsIgnoreCase("AES/GCM/NoPadding")
                || cipherSuite.equalsIgnoreCase("AES/CTR/NoPadding")
                || cipherSuite.equalsIgnoreCase("AES/CBC/PKCS5Padding")) {

            byte[] aesKey = Arrays.copyOf(keyMaterial, 32);
            return new SecretKeySpec(aesKey, "AES");
        }

        if (cipherSuite.equalsIgnoreCase("ChaCha20-Poly1305")) {
            byte[] chachaKey = Arrays.copyOf(keyMaterial, 32);
            return new SecretKeySpec(chachaKey, "ChaCha20");
        }

        throw new RuntimeException("Unsupported ciphersuite: " + cipherSuite);
    }

    public static SecretKey deriveMacKey(
            byte[] kyberSharedSecret,
            byte[] clientNonce,
            byte[] serverNonce) throws Exception {

        byte[] keyMaterial = deriveKeyMaterial(
                kyberSharedSecret,
                clientNonce,
                serverNonce,
                "RTSSP PQ MAC KEY");

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

    // ============================================================
    // PQ-SHP MESSAGE CREATION
    // ============================================================

    public static String createClientHello(
            String movieName,
            String streamEndpoint,
            String[] supportedCipherSuites,
            PublicKey clientKyberPublicKey,
            byte[] clientNonce,
            PublicKey clientDilithiumPublicKey,
            PrivateKey clientDilithiumPrivateKey) throws Exception {

        String unsignedMessage = PQ_CLIENT_HELLO + "|" +
                movieName + "|" +
                streamEndpoint + "|" +
                String.join(",", supportedCipherSuites) + "|" +
                publicKeyToBase64(clientKyberPublicKey) + "|" +
                bytesToBase64(clientNonce) + "|" +
                publicKeyToBase64(clientDilithiumPublicKey);

        byte[] signature = dilithiumSign(unsignedMessage.getBytes(), clientDilithiumPrivateKey);

        return unsignedMessage + "|" + bytesToBase64(signature);
    }

    public static boolean verifyClientHelloSignature(String[] parts) throws Exception {
        if (parts.length != 8) {
            throw new SecurityException("Invalid PQ CLIENT_HELLO format");
        }

        String unsignedMessage = parts[0] + "|" +
                parts[1] + "|" +
                parts[2] + "|" +
                parts[3] + "|" +
                parts[4] + "|" +
                parts[5] + "|" +
                parts[6];

        PublicKey clientDilithiumPublicKey = base64ToDilithiumPublicKey(parts[6]);

        byte[] receivedSignature = base64ToBytes(parts[7]);

        return dilithiumVerify(
                unsignedMessage.getBytes(),
                receivedSignature,
                clientDilithiumPublicKey);
    }

    public static String createServerHello(
            String movieName,
            String selectedCipherSuite,
            byte[] serverNonce,
            byte[] kyberEncapsulation,
            PublicKey serverDilithiumPublicKey,
            byte[] clientNonceResponse,
            PrivateKey serverDilithiumPrivateKey) throws Exception {

        String unsignedMessage = PQ_SERVER_HELLO + "|" +
                movieName + "|" +
                selectedCipherSuite + "|" +
                bytesToBase64(serverNonce) + "|" +
                bytesToBase64(kyberEncapsulation) + "|" +
                publicKeyToBase64(serverDilithiumPublicKey) + "|" +
                bytesToBase64(clientNonceResponse);

        byte[] signature = dilithiumSign(unsignedMessage.getBytes(), serverDilithiumPrivateKey);

        return unsignedMessage + "|" + bytesToBase64(signature);
    }

    public static boolean verifyServerHelloSignature(String[] parts) throws Exception {
        if (parts.length != 8) {
            throw new SecurityException("Invalid PQ SERVER_HELLO format");
        }

        String unsignedMessage = parts[0] + "|" +
                parts[1] + "|" +
                parts[2] + "|" +
                parts[3] + "|" +
                parts[4] + "|" +
                parts[5] + "|" +
                parts[6];

        PublicKey serverDilithiumPublicKey = base64ToDilithiumPublicKey(parts[5]);

        byte[] receivedSignature = base64ToBytes(parts[7]);

        return dilithiumVerify(
                unsignedMessage.getBytes(),
                receivedSignature,
                serverDilithiumPublicKey);
    }

    public static String createClientFinal(byte[] serverNonceResponse) {
        return PQ_CLIENT_FINAL + "|" +
                bytesToBase64(serverNonceResponse) + "|" +
                "START_STREAM";
    }

    public static String[] splitMessage(String message) {
        return message.split("\\|");
    }

    // ============================================================
    // OPTIONAL: TRUST CHECKING BY PUBLIC KEY FINGERPRINT
    // ============================================================

    public static String publicKeyFingerprint(PublicKey publicKey) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] fp = digest.digest(publicKey.getEncoded());
        return bytesToBase64(fp);
    }

    public static void verifyExpectedFingerprint(
            PublicKey receivedPublicKey,
            String expectedFingerprintBase64) throws Exception {

        String receivedFingerprint = publicKeyFingerprint(receivedPublicKey);

        if (!receivedFingerprint.equals(expectedFingerprintBase64)) {
            throw new SecurityException("Received PQ public key fingerprint is not trusted");
        }
    }
}