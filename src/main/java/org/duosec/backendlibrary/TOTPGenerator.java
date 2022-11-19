package org.duosec.backendlibrary;

public interface TOTPGenerator {
    String now();
    String at(final long secondsPast1970);
}
