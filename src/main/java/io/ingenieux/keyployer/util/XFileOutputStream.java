package io.ingenieux.keyployer.util;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;

import static jdk.nashorn.internal.runtime.ScriptingFunctions.exec;
import static org.apache.commons.lang3.StringUtils.isNotBlank;

public class XFileOutputStream extends FileOutputStream {
    static final Logger LOGGER = LoggerFactory.getLogger(XFileOutputStream.class);

    private final String path;

    private String owner;

    private String mode;

    public static XFileOutputStream get(String mask, Object... p) throws IOException {
        final String path = String.format(mask, (Object[]) p);

        File f = new File(path).getParentFile();

        if (! f.exists())
            f.mkdirs();

        f.mkdir();

        return new XFileOutputStream(path);
    }

    public XFileOutputStream(String path) throws FileNotFoundException {
        super(path);

        this.path = path;
    }

    public XFileOutputStream withOwner(String owner) {
        this.owner = owner;

        return this;
    }

    public XFileOutputStream withMode(String mode) {
        this.mode = mode;

        return this;
    }

    @Override
    public void close() throws IOException {
        super.close();

        try {
            if (isNotBlank(owner)) {
                exec("/bin/chown", owner, path);
            }

            if (isNotBlank(mode)) {
                exec("/bin/chmod", mode, path);
            }
        } catch (Exception exc) {
            throw new IOException(exc);
        }
    }
}
