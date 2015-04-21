package io.ingenieux.keyployer;

import io.ingenieux.keyployer.util.PasswordGenerator;
import io.ingenieux.keyployer.util.XFileOutputStream;
import org.apache.commons.io.IOUtils;
import org.docopt.Docopt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static io.ingenieux.keyployer.util.Exec.exec;
import static java.lang.String.format;
import static org.apache.commons.lang3.StringUtils.*;

public class Keyployer {
    private static final String DEPLOY_DIR = defaultDir("DEPLOY_DIR", "opt/cloudera/security");

    private static String defaultDir(String envVarName, String defaultValue) {
        String envValue = System.getenv(envVarName);

        String resultValue = stripEnd(defaultString(envValue, defaultValue), "/");

        return resultValue;
    }

    private static final Logger LOGGER = LoggerFactory.getLogger(Keyployer.class);

    private static final String USAGE = getResourceAsString("USAGE.txt");

    private static final String VERSION = getResourceAsString("VERSION.txt");

    private static final String SCRIPT_STUB = getResourceAsString("STUB.txt");

    public static final String DEFAULT_PASSWORD = "changeit";

    public static final char[] DEFAULT_PASSWORD_ARR = DEFAULT_PASSWORD.toCharArray();

    public static final KeyStore.ProtectionParameter DEFAULT_PASSWORD_PROTECTION = new KeyStore.PasswordProtection(DEFAULT_PASSWORD_ARR);

    public static final String CMAGENT_PREFIX = DEPLOY_DIR + "/cmagent/";

    private final KeyployerOptions keyployerOpts;

    private JKSRepo signedKeystore;

    private JKSRepo truststore;

    private final String password = PasswordGenerator.generateRandomPassword();

    //private final JKSRepo truststore;

    //private final JKSRepo hostsTruststore;

    private static String getResourceAsString(String name) {
        try {
            return IOUtils.toString(Keyployer.class.getResourceAsStream(name));
        } catch (Exception exc) {
            LOGGER.warn("Oops", exc);

            throw new RuntimeException(exc);
        }
    }

    public static void main(String[] args) throws Exception {
        new Keyployer(args).execute();
    }

    public Keyployer(String[] args) throws Exception {
        /*
        if (isNotBlank(System.getenv("KEYPLOYER_DEBUG"))) {
            LoggerFactory.getL
        }
        */

        Docopt docopt = new Docopt(USAGE).withHelp(true).withOptionsFirst(true).withVersion(VERSION).withExit(true);

        Map<String, Object> argsMap = docopt.parse(args);

        LOGGER.debug("argsMap: {}", argsMap);

        this.keyployerOpts = new KeyployerOptions(argsMap);

        LOGGER.debug("keyployerOpts: {}", keyployerOpts);

        this.signedKeystore = new JKSRepo(this.keyployerOpts.getSignedKeystore(), true);
        this.truststore = new JKSRepo(this.keyployerOpts.getTrustStore(), false);
    }

    private boolean isCMHost() {
        return keyployerOpts.getFqdn().equals(keyployerOpts.getCmHost());
    }

    private boolean isHueHost() {
        return keyployerOpts.getFqdn().equals(keyployerOpts.getHueHost());
    }

    private void exportForCMAgents() throws Exception {
        JKSRepo.KeyEntry cmHostEntry = signedKeystore.getAliasMap().get(keyployerOpts.getCmHost());
        XFileOutputStream outputStream = XFileOutputStream.get(DEPLOY_DIR + "/x509/cmhost-cert.pem").withMode("644").withOwner("root").build();

        IOUtils.write(cmHostEntry.asX509String(), outputStream);

        char[] passwordArr = password.toCharArray();
        KeyStore.PasswordProtection passwordProtection = new KeyStore.PasswordProtection(passwordArr);

        JKSRepo hostKeyStore = new JKSRepo();

        JKSRepo.KeyEntry keyEntry = signedKeystore.getAliasMap().get(keyployerOpts.getFqdn());
        KeyStore.Entry entry = keyEntry.getEntry();

        hostKeyStore.getKs().setEntry("cmagent", entry, passwordProtection);

        hostKeyStore.getKs().store(XFileOutputStream.get(DEPLOY_DIR + "/jks/cmagent-keystore.jks").withOwner("cloudera-scm").withMode("644").build(), passwordArr);

        IOUtils.write(password, XFileOutputStream.get(CMAGENT_PREFIX +
                "cmagent.pw").withOwner("cloudera-scm").withMode("400").build());

        {
            String cmAgentP12 = CMAGENT_PREFIX +
                    "cmagent.p12";

            XFileOutputStream outputAsP12 = XFileOutputStream.get(cmAgentP12).withOwner("cloudera-scm").withMode("600").build();

            keyEntry.writeAsP12("default", outputAsP12, password);

            exec("/usr/bin/openssl", "pkcs12", "-in", cmAgentP12, "-passin", "pass:" + password, "-nokeys", "-out", CMAGENT_PREFIX + "cmagent.pem");
            exec("/usr/bin/openssl", "pkcs12", "-in", cmAgentP12, "-passin", "pass:" + password, "-nocerts", "-passout", "pass:" + password, "-out", CMAGENT_PREFIX + "cmagent.key");
        }
    }

    public void exportCMHost(String password) throws Exception {
        char[] passwordArr = password.toCharArray();

        JKSRepo.KeyEntry keyEntry = signedKeystore.getAliasMap().get(keyployerOpts.getFqdn());

        JKSRepo cmHostKeyStore = new JKSRepo();

        cmHostKeyStore.getKs().setEntry("cmhost", keyEntry.getEntry(), new KeyStore.PasswordProtection(passwordArr));

        cmHostKeyStore.getKs().store(XFileOutputStream.get(DEPLOY_DIR + "/jks/cmhost-keystore.jks").withOwner("cloudera-scm").withMode("400").build(), passwordArr);
    }

    public void exportTrustStoreCertificates() throws Exception {
        List<String> certList = new ArrayList<>();

        for (JKSRepo.KeyEntry k : truststore.getAliasMap().values()) {
            XFileOutputStream outputStream = XFileOutputStream.get(DEPLOY_DIR + "/CAcerts/%s.pem", k.getAlias()).withMode("644").withOwner("root").build();

            String newCertificate = k.asX509String();

            certList.add(newCertificate);

            IOUtils.write(newCertificate, outputStream);
        }

        {
            JKSRepo.KeyEntry cmHostKeyEntry = signedKeystore.getAliasMap().get(keyployerOpts.getCmHost());

            certList.add(cmHostKeyEntry.asX509String());

            String certOutput = join(certList, "\n");

            IOUtils.write(certOutput, XFileOutputStream.get(CMAGENT_PREFIX + "certificates.pem").withMode("644").withOwner("root").build());
        }
    }

    public void exportHueCertificates() throws Exception {
        if (!isHueHost())
            return;

        List<String> certList = new ArrayList<>();

        for (JKSRepo.KeyEntry k : truststore.getAliasMap().values())
            certList.add(k.asX509String());

        String certOutput = join(certList);

        IOUtils.write(certOutput, XFileOutputStream.get(DEPLOY_DIR + "/hue/huetrust.pem").withMode("644").withOwner("root").build());

        String cmAgentP12 = CMAGENT_PREFIX +
                "cmagent.p12";

        exec("/usr/bin/openssl", "pkcs12", "-in", cmAgentP12, "-passin", "pass:" + password, "-nokeys", "-out", DEPLOY_DIR + "/hue/sslcert.pem");
        exec("/usr/bin/openssl", "pkcs12", "-in", cmAgentP12, "-passin", "pass:" + password, "-nocerts", "-nodes", "-passout", "pass:", "-out", DEPLOY_DIR + "/hue/sslcert.key");
    }

    public void exportTrustStore(String truststorePassword) throws Exception {
        String javaHome = System.getProperty("java.home");
        char[] truststorePasswordArr = truststorePassword.toCharArray();
        String cacertsPath = null;

        // TODO: Become another parameter
        List<File> probablePaths = Arrays.asList(new File(javaHome, "jre/lib/security/cacerts"), new File(javaHome, "lib/security/cacerts"));

        for (File f : probablePaths) {
            if (!f.exists())
                continue;

            if (!f.isFile())
                continue;

            cacertsPath = f.getPath();
        }


        JKSRepo cacerts = new JKSRepo(cacertsPath, false);

        for (JKSRepo.KeyEntry entry : truststore.getAliasMap().values()) {
            cacerts.getKs().setEntry(entry.getAlias(), entry.getEntry(), null);
        }

        cacerts.getKs().store(XFileOutputStream.get(DEPLOY_DIR + "/jks/truststore").withOwner("root").withMode("644").build(), truststorePasswordArr);
    }


    /**
     * TODO: REFACTOR THIS
     */
    private void exportPrivateKeys() throws Exception {
        for (JKSRepo.KeyEntry key : signedKeystore.getAliasMap().values()) {
            String alias = key.getAlias();
            String outputPath = format("p12/%s.p12", alias);

            { // Creates a p12 keystore with this hosts' entry
                JKSRepo hostKeyStore = new JKSRepo();

                hostKeyStore.getKs().setEntry(alias, key.getEntry(), DEFAULT_PASSWORD_PROTECTION);

                LOGGER.info("Writing key from {} into {}", alias, outputPath);

                hostKeyStore.getKs().store(new FileOutputStream(outputPath), DEFAULT_PASSWORD_ARR);
            }

            //if (isCMHost()) {
            //}

            List<String> baseArgs = Arrays.asList("/usr/bin/openssl", "pkcs12", "-in", outputPath, "-passin", "pass:" + DEFAULT_PASSWORD);

            List<String> certificate = new ArrayList<>();

            certificate.addAll(baseArgs);

            certificate.addAll(Arrays.asList("-nokeys", "-out", "pem/" + alias + ".pem"));

            List<String> privateKey = new ArrayList<>();

            privateKey.addAll(baseArgs);

            privateKey.addAll(Arrays.asList("-nocerts", "-out", "key/" + alias + ".key", "-passout", "pass:" + DEFAULT_PASSWORD));

            for (List<String> cmdList : Arrays.asList(certificate, privateKey)) {
                Process p = Runtime.getRuntime().exec(cmdList.toArray(new String[cmdList.size()]));

                int rc = p.waitFor();

                LOGGER.debug("cmd: {}; rc: {}", join(cmdList, " "), rc);
            }

        }


    }

    public void execute() {
        try {
            XFileOutputStream.setDeployPrefix(DEPLOY_DIR);

            executeInternal();
        } catch (Exception exc) {
            LOGGER.warn("execute()", exc);

            throw new RuntimeException(exc);
        }
    }

    public void executeInternal() throws Exception {
        // TODO: Allow custom key instead
        if (isCMHost()) {
            exportCMHost(password);
        }

        exportTrustStore(DEFAULT_PASSWORD);

        exportTrustStoreCertificates();

        exportForCMAgents();

        exportHueCertificates();

        writeInstallScript();
    }

    private void writeInstallScript() throws Exception {
        try (FileOutputStream fos = new FileOutputStream(DEPLOY_DIR + "/install.sh")) {
            String scriptContent = join(XFileOutputStream.dumpCommandList(), "\n") + "\n";

            scriptContent = SCRIPT_STUB + "\n\n" + scriptContent;

            IOUtils.write(scriptContent, fos);
        }
    }
}
