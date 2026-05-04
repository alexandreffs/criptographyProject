import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public class RTSSP {

    public static final byte TYPE_START = 1;
    public static final byte TYPE_DATA = 2;
    public static final byte TYPE_END = 3;
    public static final byte TYPE_ERROR = 4;

    public static final short VERSION = 1;

    private static final int GCM_NONCE_LENGTH = 12;
    private static final int CHACHA_NONCE_LENGTH = 12;
    private static final int AES_BLOCK_IV_LENGTH = 16;
    private static final int GCM_TAG_LENGTH = 128;
    private static final int AEAD_TAG_BYTES = 16;

    private static final SecureRandom random = new SecureRandom();

    public static byte[] protect(
            byte type,
            int seq,
            byte[] plaintext,
            CryptoConfig crypto) throws Exception {

        byte[] iv = generateIV(crypto);
        byte[] ciphertext;
        byte[] mac = new byte[0];

        if (crypto.cipherSuite.equalsIgnoreCase("AES/GCM/NoPadding")) {

            int ciphertextLength = plaintext.length + AEAD_TAG_BYTES;

            byte[] header = buildHeader(
                    type,
                    seq,
                    ciphertextLength,
                    iv.length,
                    0);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

            cipher.init(Cipher.ENCRYPT_MODE, crypto.key, spec);
            cipher.updateAAD(header);

            ciphertext = cipher.doFinal(plaintext);

            return concat(header, iv, ciphertext, mac);
        }

        else if (crypto.cipherSuite.equalsIgnoreCase("ChaCha20-Poly1305")) {

            int ciphertextLength = plaintext.length + AEAD_TAG_BYTES;

            byte[] header = buildHeader(
                    type,
                    seq,
                    ciphertextLength,
                    iv.length,
                    0);

            Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
            IvParameterSpec spec = new IvParameterSpec(iv);

            cipher.init(Cipher.ENCRYPT_MODE, crypto.key, spec);
            cipher.updateAAD(header);

            ciphertext = cipher.doFinal(plaintext);

            return concat(header, iv, ciphertext, mac);
        }

        else {
            Cipher cipher = Cipher.getInstance(crypto.cipherSuite);
            IvParameterSpec spec = new IvParameterSpec(iv);

            cipher.init(Cipher.ENCRYPT_MODE, crypto.key, spec);

            ciphertext = cipher.doFinal(plaintext);

            int macLength = Mac.getInstance(crypto.hmacAlgorithm).getMacLength();

            byte[] header = buildHeader(
                    type,
                    seq,
                    ciphertext.length,
                    iv.length,
                    macLength);

            mac = computeMac(crypto, header, iv, ciphertext);

            return concat(header, iv, ciphertext, mac);
        }
    }

    public static Packet unprotect(
            byte[] packetData,
            CryptoConfig crypto) throws Exception {

        ByteBuffer buffer = ByteBuffer.wrap(packetData);

        byte type = buffer.get();
        short version = buffer.getShort();
        int seq = buffer.getInt();
        int ciphertextLength = buffer.getInt();
        int ivLength = Byte.toUnsignedInt(buffer.get());
        int macLength = Byte.toUnsignedInt(buffer.get());

        if (version != VERSION) {
            throw new SecurityException("Invalid RTSSP version");
        }

        byte[] header = buildHeader(
                type,
                seq,
                ciphertextLength,
                ivLength,
                macLength);

        byte[] iv = new byte[ivLength];
        buffer.get(iv);

        byte[] ciphertext = new byte[ciphertextLength];
        buffer.get(ciphertext);

        byte[] receivedMac = new byte[macLength];

        if (macLength > 0) {
            buffer.get(receivedMac);
        }

        byte[] plaintext;

        if (crypto.cipherSuite.equalsIgnoreCase("AES/GCM/NoPadding")) {

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

            cipher.init(Cipher.DECRYPT_MODE, crypto.key, spec);
            cipher.updateAAD(header);

            plaintext = cipher.doFinal(ciphertext);
        }

        else if (crypto.cipherSuite.equalsIgnoreCase("ChaCha20-Poly1305")) {

            Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
            IvParameterSpec spec = new IvParameterSpec(iv);

            cipher.init(Cipher.DECRYPT_MODE, crypto.key, spec);
            cipher.updateAAD(header);

            plaintext = cipher.doFinal(ciphertext);
        }

        else {
            byte[] expectedMac = computeMac(crypto, header, iv, ciphertext);

            if (!Arrays.equals(receivedMac, expectedMac)) {
                throw new SecurityException("Invalid HMAC");
            }

            Cipher cipher = Cipher.getInstance(crypto.cipherSuite);
            IvParameterSpec spec = new IvParameterSpec(iv);

            cipher.init(Cipher.DECRYPT_MODE, crypto.key, spec);

            plaintext = cipher.doFinal(ciphertext);
        }

        return new Packet(type, seq, plaintext);
    }

    private static byte[] generateIV(CryptoConfig crypto) {
        int length;

        if (crypto.cipherSuite.equalsIgnoreCase("AES/GCM/NoPadding")) {
            length = GCM_NONCE_LENGTH;
        }

        else if (crypto.cipherSuite.equalsIgnoreCase("ChaCha20-Poly1305")) {
            length = CHACHA_NONCE_LENGTH;
        }

        else {
            length = AES_BLOCK_IV_LENGTH;
        }

        byte[] iv = new byte[length];
        random.nextBytes(iv);

        return iv;
    }

    private static byte[] buildHeader(
            byte type,
            int seq,
            int ciphertextLength,
            int ivLength,
            int macLength) {

        ByteBuffer buffer = ByteBuffer.allocate(1 + 2 + 4 + 4 + 1 + 1);

        buffer.put(type);
        buffer.putShort(VERSION);
        buffer.putInt(seq);
        buffer.putInt(ciphertextLength);
        buffer.put((byte) ivLength);
        buffer.put((byte) macLength);

        return buffer.array();
    }

    private static byte[] computeMac(
            CryptoConfig crypto,
            byte[] header,
            byte[] iv,
            byte[] ciphertext) throws Exception {

        Mac mac = Mac.getInstance(crypto.hmacAlgorithm);
        mac.init(crypto.macKey);

        mac.update(header);
        mac.update(iv);
        mac.update(ciphertext);

        return mac.doFinal();
    }

    private static byte[] concat(byte[]... arrays) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        for (byte[] array : arrays) {
            out.write(array);
        }

        return out.toByteArray();
    }

    public static class Packet {
        public byte type;
        public int sequenceNumber;
        public byte[] payload;

        public Packet(byte type, int sequenceNumber, byte[] payload) {
            this.type = type;
            this.sequenceNumber = sequenceNumber;
            this.payload = payload;
        }
    }
}