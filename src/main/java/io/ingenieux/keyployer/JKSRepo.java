package io.ingenieux.keyployer;

import io.ingenieux.keyployer.util.XFileOutputStream;
import org.apache.commons.codec.binary.Base64;
import sun.security.provider.X509Factory;

import java.io.FileInputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Map;
import java.util.TreeMap;

public class JKSRepo {
    public static final char[] DEFAULT_PASSWORD = "changeit".toCharArray();

    private final KeyStore ks;

    private final Map<String, KeyEntry> aliasMap = new TreeMap<>();

    public JKSRepo() throws Exception {
        this.ks = KeyStore.getInstance("JKS");
        this.ks.load(null, null);
    }

    public JKSRepo(String path, boolean bKeystore) throws Exception {
        this.ks = KeyStore.getInstance("JKS");

        this.ks.load(new FileInputStream(path), DEFAULT_PASSWORD);

        Enumeration<String> enmAlias = this.ks.aliases();

        while (enmAlias.hasMoreElements()) {
            String alias = enmAlias.nextElement();

            KeyStore.ProtectionParameter passProtection = Keyployer.DEFAULT_PASSWORD_PROTECTION;

            if (! bKeystore)
                passProtection = null;

            KeyStore.Entry entry = ks.getEntry(alias, passProtection);

            aliasMap.put(alias, new KeyEntry(alias, entry));
        }


    }

    public KeyStore getKs() {
        return ks;
    }

    public Map<String, KeyEntry> getAliasMap() {
        return aliasMap;
    }

    public class KeyEntry {
        final String alias;

        final KeyStore.Entry entry;

        public KeyEntry(String alias, KeyStore.Entry entry) {
            this.alias = alias;
            this.entry = entry;
        }

        public String getAlias() {
            return alias;
        }

        public KeyStore.Entry getEntry() {
            return entry;
        }

        public String asX509String() throws Exception {
            X509Certificate cert = (X509Certificate) getKs().getCertificate(this.getAlias());

            StringWriter outputWriter = new StringWriter();
            Base64 base64 = new Base64(70);

            PrintWriter printWriter = new PrintWriter(outputWriter);

            printWriter.println(X509Factory.BEGIN_CERT);
            printWriter.print(base64.encodeAsString(cert.getEncoded()));
            printWriter.println(X509Factory.END_CERT);

            return outputWriter.toString();
        }

        public void writeAsP12(String name, OutputStream output, String password) throws Exception {
            char[] passwordAsArr = password.toCharArray();
            KeyStore keyStore = KeyStore.getInstance("PKCS12");

            keyStore.load(null, null);

            keyStore.setEntry(name, this.getEntry(), new KeyStore.PasswordProtection(passwordAsArr));

            keyStore.store(output, passwordAsArr);
        }
    }
}
