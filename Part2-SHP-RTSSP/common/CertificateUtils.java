package common;

import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class CertificateUtils {

    public static PrivateKey loadPrivateKey(
            String keystorePath,
            String storePassword,
            String alias,
            String keyPassword) throws Exception {

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        try (FileInputStream input = new FileInputStream(keystorePath)) {
            keyStore.load(input, storePassword.toCharArray());
        }

        Key key = keyStore.getKey(alias, keyPassword.toCharArray());

        if (!(key instanceof PrivateKey)) {
            throw new RuntimeException("Private key not found for alias: " + alias);
        }

        return (PrivateKey) key;
    }

    public static X509Certificate loadCertificateFromKeystore(
            String keystorePath,
            String storePassword,
            String alias) throws Exception {

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        try (FileInputStream input = new FileInputStream(keystorePath)) {
            keyStore.load(input, storePassword.toCharArray());
        }

        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);

        if (certificate == null) {
            throw new RuntimeException("Certificate not found for alias: " + alias);
        }

        return certificate;
    }

    public static X509Certificate loadTrustedCertificate(
            String truststorePath,
            String storePassword,
            String alias) throws Exception {

        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());

        try (FileInputStream input = new FileInputStream(truststorePath)) {
            trustStore.load(input, storePassword.toCharArray());
        }

        X509Certificate certificate = (X509Certificate) trustStore.getCertificate(alias);

        if (certificate == null) {
            throw new RuntimeException("Trusted certificate not found for alias: " + alias);
        }

        return certificate;
    }

    public static void verifyCertificateIsTrusted(
            X509Certificate receivedCertificate,
            X509Certificate trustedCertificate) throws Exception {

        receivedCertificate.checkValidity();

        if (!Arrays.equals(receivedCertificate.getEncoded(), trustedCertificate.getEncoded())) {
            throw new SecurityException("Received certificate is not trusted");
        }
    }
}
