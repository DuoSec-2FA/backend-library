package org.duosec.backendlibrary;

import java.util.Arrays;

public class Main {
    public static void main(String[] args) {
        System.out.println(Arrays.toString(SecretGenerator.generate()));
    }
}