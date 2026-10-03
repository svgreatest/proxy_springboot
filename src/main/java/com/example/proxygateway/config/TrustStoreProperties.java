package com.example.proxygateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Configuration properties for the persistent BCFIPS trust store.
 * Holds file path, master password, and keystore type (BCFKS).
 */
@Component
@ConfigurationProperties(prefix = "app.truststore")
public class TrustStoreProperties {

    /**
     * Path where the master encrypted BCFKS keystore is persisted on disk.
     */
    private String path = "./data/application-truststore.bcfks";

    /**
     * Password protecting the BCFKS keystore integrity.
     */
    private String password = "changeit-bcfips-secure-store-2026";

    /**
     * Keystore format. In BCFIPS mode, BCFKS (Bouncy Castle FIPS KeyStore) is the recommended standard.
     */
    private String keystoreType = "BCFKS";

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getKeystoreType() {
        return keystoreType;
    }

    public void setKeystoreType(String keystoreType) {
        this.keystoreType = keystoreType;
    }
}
