package org.duosec.backendlibrary;

import org.apache.commons.codec.binary.Base32;

import java.security.SecureRandom;

public class SecretGenerator {
    public static final int DEFAULT_BITS = 160;
    private static final SecureRandom random = new SecureRandom();

    private SecretGenerator() {
    }

    public static byte[] generate() {
        return generate(DEFAULT_BITS);
    }

    /**
     * SHA1: 160 bits,
     * SHA256: 256 bits,
     * SHA512: 512 bits
     */
    public static byte[] generate(final int bits) {
        if (bits <= 0)
            throw new IllegalArgumentException("Bits must be greater than or equal to 0");

        byte[] bytes = new byte[bits / Byte.SIZE];
        random.nextBytes(bytes);

        Base32 encoder = new Base32();
        return encoder.encode(bytes);
    }
}
