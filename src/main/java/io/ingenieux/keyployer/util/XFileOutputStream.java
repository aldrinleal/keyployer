package io.ingenieux.keyployer.util;

import org.apache.commons.io.FilenameUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static java.util.Arrays.asList;
import static org.apache.commons.lang3.StringUtils.isEmpty;
import static org.apache.commons.lang3.StringUtils.isNotBlank;
import static org.apache.commons.lang3.StringUtils.join;

public class XFileOutputStream extends FileOutputStream {
    private static final List<String> commandList = new ArrayList<>();

    public static List<String> dumpCommandList() {
        return commandList;
    }


    static final Logger LOGGER = LoggerFactory.getLogger(XFileOutputStream.class);

    private static String DEPLOY_PREFIX = null;

    public static void setDeployPrefix(String deployPrefix) {
        DEPLOY_PREFIX = deployPrefix;
    }

    private final String path;

    public static XFileOutputStreamBuilder get(String mask, Object... p) throws IOException {
        final String path = String.format(mask, (Object[]) p);

        File f = new File(path).getParentFile();

        if (!f.exists())
            f.mkdirs();

        f.mkdir();

        return new XFileOutputStreamBuilder(path);
    }

    public static class XFileOutputStreamBuilder {
        String path;

        String mode;

        String owner;

        public XFileOutputStreamBuilder(String path) {
            this.path = path;
        }


        public XFileOutputStreamBuilder withOwner(String owner) {
            this.owner = owner;

            return this;
        }

        public XFileOutputStreamBuilder withMode(String mode) {
            this.mode = mode;

            return this;
        }

        public XFileOutputStream build() throws IOException {
            boolean hasOwner = isNotBlank(owner);
            boolean hasMode = isNotBlank(mode);

            List<String> cmd = new ArrayList<>(asList("install"));

            if (isNotBlank(owner)) {
                cmd.addAll(asList("-o", owner));
            }

            if (isNotBlank(mode)) {
                cmd.addAll(asList("-m", mode));
            }

            cmd.add("$SOURCE_DIR/" + stripDeploymentDir(path));

            cmd.add(targetPath(path));

            String cmdAsStr = join(cmd, " ");

            return new XFileOutputStream(path, cmdAsStr);
        }

        private String targetPath(String path) {
            return "$TARGET_DIR/" + FilenameUtils.getPath(stripDeploymentDir(path));
        }

        private String stripDeploymentDir(String path) {
            if (isEmpty(DEPLOY_PREFIX))
                return path;

            if (path.startsWith(DEPLOY_PREFIX)) {
                path = path.substring(1 + DEPLOY_PREFIX.length());
            }

            return path;
        }
    }

    private XFileOutputStream(String path, String cmdAsStr) throws FileNotFoundException {
        super(path);

        this.path = path;

        commandList.add(cmdAsStr);
    }
}
