package org.duosec.backendlibrary;

import java.time.Duration;

public class Main {
    public static void main(String[] args) {
        byte[] secret = SecretGenerator.generate();

        TOTP.Builder builder = new TOTP.Builder(secret);

        builder
                .withPasswordLength(6)
                .withAlgorithm(HMACAlgorithm.SHA1) // SHA256 and SHA512 are also supported
                .withPeriod(Duration.ofSeconds(30));

        TOTP totp = builder.build();
        String code = totp.now();
        boolean isValid = totp.verify(code);
        System.out.println(isValid);
    }
}