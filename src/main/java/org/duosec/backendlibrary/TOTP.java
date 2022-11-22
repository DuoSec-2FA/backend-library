package org.duosec.backendlibrary;

import org.apache.commons.codec.binary.Base32;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

public class TOTP implements TOTPGenerator, TOTPVerifier {
    private static final int DEFAULT_PASSWORD_LENGTH = 6;
    private static final HMACAlgorithm DEFAULT_HMAC_ALGORITHM = HMACAlgorithm.SHA1;
    private static final Duration DEFAULT_PERIOD = Duration.ofSeconds(30);

    protected final int passwordLength;
    protected final HMACAlgorithm algorithm;
    protected final byte[] secret;
    private final Duration period;

    private TOTP(final Builder builder) {
        this.passwordLength = builder.passwordLength;
        this.algorithm = builder.algorithm;
        this.secret = builder.secret;
        this.period = builder.period;
    }

    private String generate(final long counter) throws IllegalStateException {
        if (counter < 0)
            throw new IllegalArgumentException("Counter must be greater than or equal to 0");

        byte[] secretBytes = decodeBase32(secret);
        byte[] counterBytes = longToBytes(counter);

        byte[] hash;

        try {
            hash = generateHash(secretBytes, counterBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException();
        }

        return getCodeFromHash(hash);
    }

    private byte[] decodeBase32(final byte[] value) {
        Base32 codec = new Base32();
        return codec.decode(value);
    }

    private byte[] longToBytes(final long value) {
        return ByteBuffer.allocate(Long.BYTES).putLong(value).array();
    }

    private byte[] generateHash(final byte[] secret, final byte[] data) throws InvalidKeyException, NoSuchAlgorithmException {
        // Create a secret key with correct SHA algorithm
        SecretKeySpec signKey = new SecretKeySpec(secret, "RAW");
        // Mac is 'message authentication code' algorithm (RFC 2104)
        Mac mac = Mac.getInstance(algorithm.getHMACName());
        mac.init(signKey);
        // Hash data with generated sign key
        return mac.doFinal(data);
    }

    private String getCodeFromHash(final byte[] hash) {
        int mask = ~(~0 << 4);

        byte lastByte = hash[hash.length - 1];
        int offset = lastByte & mask;

        // Get 4 bytes from hash from offset to offset + 3
        byte[] truncatedHashInBytes = {hash[offset], hash[offset + 1], hash[offset + 2], hash[offset + 3]};

        // Wrap in ByteBuffer to convert bytes to long
        ByteBuffer byteBuffer = ByteBuffer.wrap(truncatedHashInBytes);
        long truncatedHash = byteBuffer.getInt();

        // Mask most significant bit
        truncatedHash &= 0x7FFFFFFF;

        // Modulo (%) truncatedHash by 10^passwordLength
        truncatedHash %= Math.pow(10, passwordLength);

        // Left pad with 0s for an n-digit code
        return String.format("%0" + passwordLength + "d", truncatedHash);
    }

    // generate a time-based one-time password for current time interval
    public String now() throws IllegalStateException {
        long counter = calculateCounter(period);
        return generate(counter);
    }

    // generate a time-based one-time password for a specific time based on seconds past 1970
    public String at(final long secondsPast1970) throws IllegalArgumentException {
        if (!validateTime(secondsPast1970))
            throw new IllegalArgumentException("Time must be above zero");

        long counter = calculateCounter(secondsPast1970, period);
        return generate(counter);
    }

    private long calculateCounter(final long secondsPast1970, final Duration period) {
        return TimeUnit.SECONDS.toMillis(secondsPast1970) / period.toMillis();
    }

    private long calculateCounter(final Duration period) {
        return System.currentTimeMillis() / period.toMillis();
    }

    private boolean validateTime(final long time) {
        return time > 0;
    }


    public boolean verify(final String code, final long counter, final int delayWindow) {
        if (code.length() != passwordLength) return false;

        for (int i = -delayWindow; i <= delayWindow; i++) {
            String currentCode = generate(counter + i);
            if (code.equals(currentCode)) return true;
        }

        return false;
    }

    public boolean verify(final String code) {
        long counter = calculateCounter(period);
        return verify(code, counter, 0);
    }

    public boolean verify(final String code, final int delayWindow) {
        long counter = calculateCounter(period);
        return verify(code, counter, delayWindow);
    }

    @Override
    public String toString() {
        return "TOTP{" +
                "passwordLength=" + passwordLength +
                ", algorithm=" + algorithm +
                ", period=" + period +
                ", secret=" + Arrays.toString(secret) +
                '}';
    }

    public static class Builder {
        private final byte[] secret;
        private int passwordLength;
        private HMACAlgorithm algorithm;
        private Duration period;

        public Builder(byte[] secret) {
            this.secret = secret;
            this.passwordLength = DEFAULT_PASSWORD_LENGTH;
            this.algorithm = DEFAULT_HMAC_ALGORITHM;
            this.period = DEFAULT_PERIOD;
        }

        public Builder withPeriod(Duration period) {
            if (period.getSeconds() < 1) throw new IllegalArgumentException("Period must be at least 1 second");
            this.period = period;
            return this;
        }

        public Builder withPasswordLength(final int passwordLength) {
            this.passwordLength = passwordLength;
            return getBuilder();
        }

        public Builder withAlgorithm(final HMACAlgorithm algorithm) {
            this.algorithm = algorithm;
            return getBuilder();
        }

        public TOTP build() {
            return new TOTP(this);
        }

        protected Builder getBuilder() {
            return this;
        }
    }
}
