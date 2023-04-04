package io.ingenieux.keyployer.util;

import io.openpixee.security.SystemCommand;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public class Exec {
    private static final Logger LOGGER = LoggerFactory.getLogger(Exec.class);

    public static void exec(String... args) throws InterruptedException, IOException {
        String argsAsString = StringUtils.join(args, " ");

        LOGGER.info("Running: {}", argsAsString);

        int rc = SystemCommand.runCommand(Runtime.getRuntime(), args).waitFor();

        if (0 != rc) {
            throw new RuntimeException("Unexpected result: " + rc + " for command: " + argsAsString);
        }
    }
}
