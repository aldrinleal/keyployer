package io.ingenieux.keyployer;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Map;

public class KeyployerOptions {
    String fqdn;

    public String getFqdn() {
        return fqdn;
    }

    public void setFqdn(String fqdn) {
        this.fqdn = fqdn;
    }

    String cmHost;

    public String getCmHost() {
        return cmHost;
    }

    public void setCmHost(String cmHost) {
        this.cmHost = cmHost;
    }

    String hueHost;

    public String getHueHost() {
        return hueHost;
    }

    public void setHueHost(String hueHost) {
        this.hueHost = hueHost;
    }

    String signedKeystore;

    public String getSignedKeystore() {
        return signedKeystore;
    }

    public void setSignedKeystore(String signedKeystore) {
        this.signedKeystore = signedKeystore;
    }

    String trustStore;

    public String getTrustStore() {
        return trustStore;
    }

    public void setTrustStore(String trustStore) {
        this.trustStore = trustStore;
    }

    String hostsTrustStore;

    public String getHostsTrustStore() {
        return hostsTrustStore;
    }

    public void setHostsTrustStore(String hostsTrustStore) {
        this.hostsTrustStore = hostsTrustStore;
    }

    public KeyployerOptions() throws IOException {
        setFqdn(InetAddress.getLocalHost().getHostName());
    }

    public KeyployerOptions(Map<String, Object> args) throws IOException {
        this();
        loadFrom(args);
    }

    private void loadFrom(Map<String, Object> args) {
        if (null != args.get("--fqdn"))
            setFqdn((String) args.get("--fqdn"));

        if (null != args.get("--signed"))
            setSignedKeystore((String) args.get("--signed"));

        if (null != args.get("--truststore"))
            setTrustStore((String) args.get("--truststore"));

        if (null != args.get("--hue-host"))
            setHueHost((String) args.get("--hue-host"));

        if (null != args.get("--cmhost"))
            setCmHost((String) args.get("--cmhost"));
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this, ToStringStyle.SHORT_PREFIX_STYLE);
    }
}
