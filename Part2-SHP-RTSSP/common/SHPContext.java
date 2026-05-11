package common;

import javax.crypto.SecretKey;

public class SHPContext {

    public String movieName;
    public String selectedCipherSuite;

    public SecretKey encryptionKey;
    public SecretKey macKey;

    public byte[] clientNonce;
    public byte[] serverNonce;

    public CryptoConfig toCryptoConfig() {
        CryptoConfig crypto = new CryptoConfig();

        crypto.movieName = movieName;
        crypto.cipherSuite = selectedCipherSuite;
        crypto.key = encryptionKey;

        if (macKey != null) {
            crypto.hmacAlgorithm = "HmacSHA256";
            crypto.macKey = macKey;
        }

        return crypto;
    }
}
