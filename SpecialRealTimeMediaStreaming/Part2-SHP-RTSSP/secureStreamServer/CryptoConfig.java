
import java.io.*;
import java.util.*;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class CryptoConfig {

    public String movieName;
    public String cipherSuite;
    public SecretKey key;

    public String hmacAlgorithm;
    public SecretKey macKey;

    public boolean isAEAD() {
        return cipherSuite.equalsIgnoreCase("AES/GCM/NoPadding")
                || cipherSuite.equalsIgnoreCase("ChaCha20-Poly1305");
    }

    public boolean usesAES() {
        return cipherSuite.toUpperCase().contains("AES");
    }

    public boolean usesChaCha() {
        return cipherSuite.toUpperCase().contains("CHACHA20");
    }

    public static Map<String, CryptoConfig> loadAll(String filename) throws Exception {
        Map<String, CryptoConfig> configs = new HashMap<>();

        BufferedReader reader = new BufferedReader(new FileReader(filename));

        String line;
        CryptoConfig current = null;
        String currentMovie = null;

        while ((line = reader.readLine()) != null) {
            line = removeComment(line).trim();

            if (line.isEmpty()) {
                continue;
            }

            if (line.startsWith("<") && !line.startsWith("</")) {
                currentMovie = line.replace("<", "")
                        .replace(">", "")
                        .replace(".encrypted", "")
                        .trim();

                current = new CryptoConfig();
                current.movieName = currentMovie;
            }

            else if (line.startsWith("</")) {
                validateConfig(current);
                configs.put(currentMovie, current);

                current = null;
                currentMovie = null;
            }

            else if (current != null) {
                int idx = line.indexOf(":");
                if (idx == -1) {
                    continue;
                }

                String field = line.substring(0, idx).trim().toLowerCase();
                String value = line.substring(idx + 1).trim();

                switch (field) {
                    case "ciphersuite":
                        current.cipherSuite = value;
                        break;

                    case "key":
                        byte[] keyBytes = hexToBytes(value);

                        if (current.cipherSuite == null) {
                            throw new RuntimeException("ciphersuite must appear before key");
                        }

                        if (current.usesAES()) {
                            current.key = new SecretKeySpec(keyBytes, "AES");
                        } else if (current.usesChaCha()) {
                            current.key = new SecretKeySpec(keyBytes, "ChaCha20");
                        } else {
                            throw new RuntimeException("Unsupported ciphersuite: " + current.cipherSuite);
                        }
                        break;

                    case "hmac":
                        current.hmacAlgorithm = normalizeHmac(value);
                        break;

                    case "mackey":
                        byte[] macKeyBytes = hexToBytes(value);

                        if (current.hmacAlgorithm == null) {
                            current.hmacAlgorithm = "HmacSHA256";
                        }

                        current.macKey = new SecretKeySpec(macKeyBytes, current.hmacAlgorithm);
                        break;
                }
            }
        }

        reader.close();
        return configs;
    }

    private static void validateConfig(CryptoConfig config) {
        if (config == null) {
            return;
        }

        if (config.cipherSuite == null) {
            throw new RuntimeException("Missing ciphersuite for " + config.movieName);
        }

        if (config.key == null) {
            throw new RuntimeException("Missing key for " + config.movieName);
        }

        if (!config.isAEAD()) {
            if (config.hmacAlgorithm == null || config.macKey == null) {
                throw new RuntimeException(
                        "CipherSuite " + config.cipherSuite +
                                " requires hmac and mackey for " + config.movieName);
            }
        }
    }

    private static String removeComment(String line) {
        int idx = line.indexOf("//");
        if (idx >= 0) {
            return line.substring(0, idx);
        }
        return line;
    }

    private static String normalizeHmac(String value) {
        value = value.trim();

        if (value.equalsIgnoreCase("HMACSHA256")) {
            return "HmacSHA256";
        }

        if (value.equalsIgnoreCase("HMACSHA512")) {
            return "HmacSHA512";
        }

        return value;
    }

    private static byte[] hexToBytes(String hex) {
        hex = hex.replace(" ", "").replace(":", "");

        if (hex.length() % 2 != 0) {
            throw new RuntimeException("Invalid hex key length");
        }

        byte[] data = new byte[hex.length() / 2];

        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }

        return data;
    }
}