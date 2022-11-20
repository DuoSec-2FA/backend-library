package org.duosec.backendlibrary;

import java.time.Duration;
import java.util.Arrays;

public class TOTP {
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
