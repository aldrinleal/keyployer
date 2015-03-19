package io.ingenieux.keyployer.util;

import org.apache.commons.lang3.RandomStringUtils;

public class PasswordGenerator {
    public static String generateRandomPassword() {
        return RandomStringUtils.random(128, true, true);
    }
}
