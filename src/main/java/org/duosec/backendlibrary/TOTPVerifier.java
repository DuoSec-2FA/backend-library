package org.duosec.backendlibrary;

public interface TOTPVerifier {
    boolean verify(final String code);
    boolean verify(final String code, final int delayWindow);
}
