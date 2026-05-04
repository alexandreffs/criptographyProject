package secureUDPproxy;

import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.*;
import java.io.ByteArrayInputStream;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class SHP {

    public static final String SHP_CLIENT_HELLO = "SHP_CLIENT_HELLO";
    public static final String SHP_SERVER_HELLO = "SHP_SERVER_HELLO";
    public static final String SHP_CLIENT_FINAL = "SHP_CLIENT_FINAL";
    public static final String SHP_ERROR = "SHP_ERROR";

    private static final int NONCE_SIZE = 32;

    public static KeyPair generateECDHKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        keyPairGenerator.initialize(ecSpec);
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] generateNonce() {
        byte[] nonce = new byte[NONCE_SIZE];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    public static String publicKeyToBase64(PublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    public static PublicKey base64ToPublicKey(String encodedKey) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(encodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        return keyFactory.generatePublic(keySpec);
    }

    public static String certificateToBase64(X509Certificate certificate) throws Exception {
        return Base64.getEncoder().encodeToString(certificate.getEncoded());
    }

    public static X509Certificate base64ToCertificate(String value) throws Exception {
        byte[] certBytes = Base64.getDecoder().decode(value);

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

        return (X509Certificate) certificateFactory.generateCertificate(
                new ByteArrayInputStream(certBytes));
    }

    public static byte[] computeSharedSecret(
            PrivateKey privateKey,
            PublicKey peerPublicKey) throws Exception {

        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");

        keyAgreement.init(privateKey);
        keyAgreement.doPhase(peerPublicKey, true);

        return keyAgreement.generateSecret();
    }

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

            return new SecretKeySpec(Arrays.copyOf(keyMaterial, 32), "AES");
        }

        else if (cipherSuite.equalsIgnoreCase("ChaCha20-Poly1305")) {
            return new SecretKeySpec(Arrays.copyOf(keyMaterial, 32), "ChaCha20");
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

        return new SecretKeySpec(Arrays.copyOf(keyMaterial, 32), "HmacSHA256");
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

    public static byte[] createNonceResponse(byte[] nonce) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        digest.update(nonce);
        digest.update("SHP NONCE RESPONSE".getBytes());

        return digest.digest();
    }

    public static boolean verifyNonceResponse(
            byte[] nonce,
            byte[] response) throws Exception {

        return Arrays.equals(createNonceResponse(nonce), response);
    }

    public static byte[] sign(
            byte[] data,
            PrivateKey privateKey) throws Exception {

        Signature signature = Signature.getInstance("SHA256withECDSA");

        signature.initSign(privateKey);
        signature.update(data);

        return signature.sign();
    }

    public static boolean verifySignature(
            byte[] data,
            byte[] receivedSignature,
            PublicKey publicKey) throws Exception {

        Signature signature = Signature.getInstance("SHA256withECDSA");

        signature.initVerify(publicKey);
        signature.update(data);

        return signature.verify(receivedSignature);
    }

    public static String createClientHello(
            String movieName,
            String streamEndpoint,
            String[] supportedCipherSuites,
            PublicKey clientECDHPublicKey,
            byte[] clientNonce,
            X509Certificate clientCertificate,
            PrivateKey clientSigningPrivateKey) throws Exception {

        String unsignedMessage = SHP_CLIENT_HELLO + "|" +
                movieName + "|" +
                streamEndpoint + "|" +
                String.join(",", supportedCipherSuites) + "|" +
                publicKeyToBase64(clientECDHPublicKey) + "|" +
                Base64.getEncoder().encodeToString(clientNonce) + "|" +
                certificateToBase64(clientCertificate);

        byte[] signature = sign(
                unsignedMessage.getBytes(),
                clientSigningPrivateKey);

        return unsignedMessage + "|" +
                Base64.getEncoder().encodeToString(signature);
    }

    public static boolean verifyClientHelloSignature(String[] parts) throws Exception {
        if (parts.length != 8) {
            throw new SecurityException("Invalid CLIENT_HELLO format");
        }

        String unsignedMessage = parts[0] + "|" +
                parts[1] + "|" +
                parts[2] + "|" +
                parts[3] + "|" +
                parts[4] + "|" +
                parts[5] + "|" +
                parts[6];

        X509Certificate clientCertificate = base64ToCertificate(parts[6]);
        byte[] signature = base64ToBytes(parts[7]);

        return verifySignature(
                unsignedMessage.getBytes(),
                signature,
                clientCertificate.getPublicKey());
    }

    public static String createServerHello(
            String movieName,
            String selectedCipherSuite,
            PublicKey serverECDHPublicKey,
            byte[] serverNonce,
            byte[] clientNonceResponse,
            X509Certificate serverCertificate,
            PrivateKey serverSigningPrivateKey) throws Exception {

        String unsignedMessage = SHP_SERVER_HELLO + "|" +
                movieName + "|" +
                selectedCipherSuite + "|" +
                publicKeyToBase64(serverECDHPublicKey) + "|" +
                Base64.getEncoder().encodeToString(serverNonce) + "|" +
                Base64.getEncoder().encodeToString(clientNonceResponse) + "|" +
                certificateToBase64(serverCertificate);

        byte[] signature = sign(
                unsignedMessage.getBytes(),
                serverSigningPrivateKey);

        return unsignedMessage + "|" +
                Base64.getEncoder().encodeToString(signature);
    }

    public static boolean verifyServerHelloSignature(String[] parts) throws Exception {
        if (parts.length != 8) {
            throw new SecurityException("Invalid SERVER_HELLO format");
        }

        String unsignedMessage = parts[0] + "|" +
                parts[1] + "|" +
                parts[2] + "|" +
                parts[3] + "|" +
                parts[4] + "|" +
                parts[5] + "|" +
                parts[6];

        X509Certificate serverCertificate = base64ToCertificate(parts[6]);
        byte[] signature = base64ToBytes(parts[7]);

        return verifySignature(
                unsignedMessage.getBytes(),
                signature,
                serverCertificate.getPublicKey());
    }

    public static String createClientFinal(byte[] serverNonceResponse) {
        return SHP_CLIENT_FINAL + "|" +
                Base64.getEncoder().encodeToString(serverNonceResponse) + "|" +
                "START_STREAM";
    }

    public static String[] splitMessage(String message) {
        return message.split("\\|");
    }

    public static byte[] base64ToBytes(String value) {
        return Base64.getDecoder().decode(value);
    }
}

// package secureUDPproxy;

// import java.security.*;
// import java.security.spec.*;
// import java.util.*;
// import javax.crypto.*;
// import javax.crypto.spec.SecretKeySpec;

// public class SHP {

// public static final String SHP_CLIENT_HELLO = "SHP_CLIENT_HELLO";
// public static final String SHP_SERVER_HELLO = "SHP_SERVER_HELLO";
// public static final String SHP_CLIENT_FINAL = "SHP_CLIENT_FINAL";

// private static final int NONCE_SIZE = 32;

// // ------------------------------------------------------------
// // ECDH KEY PAIR GENERATION
// // ------------------------------------------------------------

// public static KeyPair generateECDHKeyPair() throws Exception {
// KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
// ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
// keyPairGenerator.initialize(ecSpec);
// return keyPairGenerator.generateKeyPair();
// }

// // ------------------------------------------------------------
// // NONCES
// // ------------------------------------------------------------

// public static byte[] generateNonce() {
// byte[] nonce = new byte[NONCE_SIZE];
// new SecureRandom().nextBytes(nonce);
// return nonce;
// }

// // ------------------------------------------------------------
// // PUBLIC KEY ENCODING / DECODING
// // ------------------------------------------------------------

// public static String publicKeyToBase64(PublicKey publicKey) {
// return Base64.getEncoder().encodeToString(publicKey.getEncoded());
// }

// public static PublicKey base64ToPublicKey(String encodedKey) throws Exception
// {
// byte[] keyBytes = Base64.getDecoder().decode(encodedKey);

// KeyFactory keyFactory = KeyFactory.getInstance("EC");
// X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);

// return keyFactory.generatePublic(keySpec);
// }

// // ------------------------------------------------------------
// // ECDH SHARED SECRET
// // ------------------------------------------------------------

// public static byte[] computeSharedSecret(PrivateKey privateKey, PublicKey
// peerPublicKey) throws Exception {
// KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");

// keyAgreement.init(privateKey);
// keyAgreement.doPhase(peerPublicKey, true);

// return keyAgreement.generateSecret();
// }

// // ------------------------------------------------------------
// // KEY DERIVATION
// // ------------------------------------------------------------

// public static SecretKey deriveEncryptionKey(
// byte[] sharedSecret,
// byte[] clientNonce,
// byte[] serverNonce,
// String cipherSuite) throws Exception {

// byte[] keyMaterial = deriveKeyMaterial(
// sharedSecret,
// clientNonce,
// serverNonce,
// "RTSSP ENCRYPTION KEY");

// if (cipherSuite.equalsIgnoreCase("AES/GCM/NoPadding")
// || cipherSuite.equalsIgnoreCase("AES/CTR/NoPadding")
// || cipherSuite.equalsIgnoreCase("AES/CBC/PKCS5Padding")) {

// byte[] aesKey = Arrays.copyOf(keyMaterial, 32); // 256-bit AES
// return new SecretKeySpec(aesKey, "AES");
// }

// else if (cipherSuite.equalsIgnoreCase("ChaCha20-Poly1305")) {
// byte[] chachaKey = Arrays.copyOf(keyMaterial, 32); // 256-bit ChaCha20
// return new SecretKeySpec(chachaKey, "ChaCha20");
// }

// else {
// throw new RuntimeException("Unsupported ciphersuite: " + cipherSuite);
// }
// }

// public static SecretKey deriveMacKey(
// byte[] sharedSecret,
// byte[] clientNonce,
// byte[] serverNonce) throws Exception {

// byte[] keyMaterial = deriveKeyMaterial(
// sharedSecret,
// clientNonce,
// serverNonce,
// "RTSSP MAC KEY");

// byte[] macKey = Arrays.copyOf(keyMaterial, 32);
// return new SecretKeySpec(macKey, "HmacSHA256");
// }

// private static byte[] deriveKeyMaterial(
// byte[] sharedSecret,
// byte[] clientNonce,
// byte[] serverNonce,
// String label) throws Exception {

// MessageDigest digest = MessageDigest.getInstance("SHA-256");

// digest.update(sharedSecret);
// digest.update(clientNonce);
// digest.update(serverNonce);
// digest.update(label.getBytes());

// return digest.digest();
// }

// // ------------------------------------------------------------
// // CIPHERSUITE NEGOTIATION
// // ------------------------------------------------------------

// public static String chooseCipherSuite(String[] clientSuites, String[]
// serverSuites) {
// for (String clientSuite : clientSuites) {
// for (String serverSuite : serverSuites) {
// if (clientSuite.trim().equalsIgnoreCase(serverSuite.trim())) {
// return serverSuite.trim();
// }
// }
// }

// throw new RuntimeException("No common ciphersuite found");
// }

// public static boolean needsMacKey(String cipherSuite) {
// return cipherSuite.equalsIgnoreCase("AES/CTR/NoPadding")
// || cipherSuite.equalsIgnoreCase("AES/CBC/PKCS5Padding");
// }

// // ------------------------------------------------------------
// // MESSAGE CREATION
// // ------------------------------------------------------------

// public static String createClientHello(
// String movieName,
// String[] supportedCipherSuites,
// PublicKey clientECDHPublicKey,
// byte[] clientNonce) {
// return SHP_CLIENT_HELLO + "|" +
// movieName + "|" +
// String.join(",", supportedCipherSuites) + "|" +
// publicKeyToBase64(clientECDHPublicKey) + "|" +
// Base64.getEncoder().encodeToString(clientNonce);
// }

// public static String createServerHello(
// String movieName,
// String selectedCipherSuite,
// PublicKey serverECDHPublicKey,
// byte[] serverNonce,
// byte[] clientNonceResponse) {
// return SHP_SERVER_HELLO + "|" +
// movieName + "|" +
// selectedCipherSuite + "|" +
// publicKeyToBase64(serverECDHPublicKey) + "|" +
// Base64.getEncoder().encodeToString(serverNonce) + "|" +
// Base64.getEncoder().encodeToString(clientNonceResponse);
// }

// public static String createClientFinal(byte[] serverNonceResponse) {
// return SHP_CLIENT_FINAL + "|" +
// Base64.getEncoder().encodeToString(serverNonceResponse) + "|" +
// "START_STREAM";
// }

// // ------------------------------------------------------------
// // SIMPLE NONCE RESPONSE
// // ------------------------------------------------------------

// public static byte[] createNonceResponse(byte[] nonce) throws Exception {
// MessageDigest digest = MessageDigest.getInstance("SHA-256");
// digest.update(nonce);
// digest.update("SHP NONCE RESPONSE".getBytes());
// return digest.digest();
// }

// public static boolean verifyNonceResponse(byte[] nonce, byte[] response)
// throws Exception {
// byte[] expected = createNonceResponse(nonce);
// return Arrays.equals(expected, response);
// }

// // ------------------------------------------------------------
// // MESSAGE PARSING HELPERS
// // ------------------------------------------------------------

// public static String[] splitMessage(String message) {
// return message.split("\\|");
// }

// public static byte[] base64ToBytes(String value) {
// return Base64.getDecoder().decode(value);
// }
// }