package com.example.proxygateway.ssl;

import com.example.proxygateway.config.BcfipsSecurityConfig;
import com.example.proxygateway.config.TrustStoreProperties;
import com.example.proxygateway.model.CertificateDetail;
import com.example.proxygateway.model.TrustStoreEntry;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Educational Persistent Trust Store Service.
 *
 * <p>Manages the master encrypted BCFKS (Bouncy Castle FIPS KeyStore) on disk.</p>
 *
 * <p>Key Invariants:</p>
 * <ol>
 *   <li>The persistent store is NEVER modified during speculative or failed connection tests.</li>
 *   <li>Only when the 2-step verification succeeds end-to-end is {@link #commitTrustAnchor} called.</li>
 *   <li>Only the exact active {@link java.security.cert.TrustAnchor} (Root CA) is added.</li>
 *   <li>Dynamic reloading: updating the keystore updates the active in-memory SSLContext
 *       without requiring application restarts.</li>
 * </ol>
 */
@Service
public class PersistentTrustStoreService {

    private static final Logger log = LoggerFactory.getLogger(PersistentTrustStoreService.class);

    private final TrustStoreProperties properties;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    private KeyStore masterKeyStore;
    private SSLContext masterSslContext;

    public PersistentTrustStoreService(TrustStoreProperties properties) {
        this.properties = properties;
    }

    @PostConstruct
    public void init() {
        lock.writeLock().lock();
        try {
            log.info("📂 Initializing Persistent BCFKS TrustStore from: {}", properties.getPath());
            File file = new File(properties.getPath());
            File parentDir = file.getParentFile();
            if (parentDir != null && !parentDir.exists()) {
                parentDir.mkdirs();
            }

            KeyStore ks = KeyStore.getInstance(properties.getKeystoreType(), BcfipsSecurityConfig.BCFIPS_PROVIDER_NAME);

            if (file.exists() && file.length() > 0) {
                log.info("📂 Loading existing BCFKS keystore from disk ({} bytes)", file.length());
                try (InputStream is = new FileInputStream(file)) {
                    ks.load(is, properties.getPassword().toCharArray());
                }
            } else {
                log.info("📂 Keystore file does not exist. Creating new empty BCFKS keystore and seeding with JVM cacerts...");
                ks.load(null, properties.getPassword().toCharArray());
                seedDefaultSystemTrust(ks);
                saveKeyStoreToDisk(ks, file);
            }

            this.masterKeyStore = ks;
            this.masterSslContext = buildSslContext(ks);
            log.info("✅ Master BCFKS TrustStore initialized successfully. Current entries: {}", listEntries().size());
        } catch (Exception e) {
            log.error("❌ Failed to initialize Persistent BCFKS TrustStore: {}", e.getMessage(), e);
            throw new IllegalStateException("Persistent TrustStore initialization failed", e);
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Seeds default public CA certificates from the JVM's standard cacerts so standard
     * internet sites (e.g. google.com, httpbin.org) can be trusted by default.
     */
    private void seedDefaultSystemTrust(KeyStore targetKs) {
        try {
            String defaultCacertsPath = System.getProperty("java.home") + "/lib/security/cacerts";
            File cacertsFile = new File(defaultCacertsPath);
            if (cacertsFile.exists()) {
                KeyStore defaultKs = null;
                // Try JKS first (standard for JVM cacerts), fallback to PKCS12
                String[] formats = new String[]{"JKS", "PKCS12"};
                for (String format : formats) {
                    try (InputStream is = new FileInputStream(cacertsFile)) {
                        KeyStore candidateKs = KeyStore.getInstance(format);
                        candidateKs.load(is, "changeit".toCharArray());
                        defaultKs = candidateKs;
                        break;
                    } catch (Exception ignored) {}
                }

                if (defaultKs != null) {
                    int count = 0;
                    Enumeration<String> aliases = defaultKs.aliases();
                    while (aliases.hasMoreElements()) {
                        String alias = aliases.nextElement();
                        if (defaultKs.isCertificateEntry(alias)) {
                            targetKs.setCertificateEntry("system-" + alias, defaultKs.getCertificate(alias));
                            count++;
                        }
                    }
                    log.info("🌱 Seeded {} standard JVM trust anchors into BCFKS keystore", count);
                }
            }
        } catch (Exception e) {
            log.warn("⚠️ Could not seed system cacerts into BCFKS store: {}", e.getMessage());
        }
    }

    /**
     * Atomically commits a verified TrustAnchor into the persistent BCFKS keystore.
     * Guaranteed to only be invoked after end-to-end HTTP verification succeeds.
     */
    public TrustStoreEntry commitTrustAnchor(X509Certificate rootCa, String alias) throws Exception {
        lock.writeLock().lock();
        try {
            if (alias == null || alias.trim().isEmpty()) {
                alias = "ca-" + CertificateInspector.getSha256Fingerprint(rootCa).replace(":", "").substring(0, 12).toLowerCase();
            }

            LogCollector.log("💾", "[PERSISTENCE] Committing TrustAnchor to BCFKS Keystore: alias='{}'", alias);
            LogCollector.log("   ", "Subject: '{}'", rootCa.getSubjectX500Principal().getName());
            LogCollector.log("   ", "SHA-256: '{}'", CertificateInspector.getSha256Fingerprint(rootCa));

            masterKeyStore.setCertificateEntry(alias, rootCa);
            saveKeyStoreToDisk(masterKeyStore, new File(properties.getPath()));

            // Reload SSLContext dynamically
            this.masterSslContext = buildSslContext(masterKeyStore);

            LogCollector.log("🎉", "TrustAnchor committed and active SSLContext reloaded successfully!");

            return toEntry(alias, rootCa);
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Removes an alias from the BCFKS keystore and persists changes to disk.
     */
    public boolean deleteTrustAnchor(String alias) {
        lock.writeLock().lock();
        try {
            if (!masterKeyStore.containsAlias(alias)) {
                return false;
            }
            masterKeyStore.deleteEntry(alias);
            saveKeyStoreToDisk(masterKeyStore, new File(properties.getPath()));
            this.masterSslContext = buildSslContext(masterKeyStore);
            log.info("🗑️ Removed trust anchor '{}' and reloaded master SSLContext", alias);
            return true;
        } catch (Exception e) {
            log.error("Failed to delete alias '{}': {}", alias, e.getMessage());
            return false;
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Lists all active trust anchors in the persistent keystore.
     */
    public List<TrustStoreEntry> listEntries() {
        lock.readLock().lock();
        try {
            List<TrustStoreEntry> list = new ArrayList<>();
            Enumeration<String> aliases = masterKeyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (masterKeyStore.isCertificateEntry(alias)) {
                    X509Certificate cert = (X509Certificate) masterKeyStore.getCertificate(alias);
                    list.add(toEntry(alias, cert));
                }
            }
            return list;
        } catch (Exception e) {
            log.error("Failed to list keystore entries: {}", e.getMessage());
            return List.of();
        } finally {
            lock.readLock().unlock();
        }
    }

    public KeyStore getMasterKeyStore() {
        lock.readLock().lock();
        try {
            return masterKeyStore;
        } finally {
            lock.readLock().unlock();
        }
    }

    public SSLContext getMasterSslContext() {
        lock.readLock().lock();
        try {
            return masterSslContext;
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Retrieves full cryptographic details and educational explanation for a specific trust anchor.
     */
    public CertificateDetail getEntryDetail(String alias) {
        lock.readLock().lock();
        try {
            if (!masterKeyStore.containsAlias(alias)) {
                return null;
            }
            X509Certificate cert = (X509Certificate) masterKeyStore.getCertificate(alias);
            if (cert == null) return null;
            return CertificateInspector.toDetail(alias, cert);
        } catch (Exception e) {
            log.error("Failed to load details for alias '{}': {}", alias, e.getMessage());
            return null;
        } finally {
            lock.readLock().unlock();
        }
    }

    private TrustStoreEntry toEntry(String alias, X509Certificate cert) {
        boolean systemRoot = alias != null && alias.startsWith("system-");
        String keyAlg = cert.getPublicKey() != null ? cert.getPublicKey().getAlgorithm() : "UNKNOWN";
        int keySize = CertificateInspector.getKeySize(cert.getPublicKey());
        return new TrustStoreEntry(
                alias,
                cert.getSubjectX500Principal().getName(),
                cert.getIssuerX500Principal().getName(),
                cert.getSerialNumber().toString(16),
                CertificateInspector.getSha256Fingerprint(cert),
                cert.getNotAfter().toInstant(),
                cert.getNotBefore().toInstant(),
                CertificateInspector.isSelfSigned(cert),
                systemRoot,
                keyAlg,
                keySize
        );
    }

    private void saveKeyStoreToDisk(KeyStore ks, File targetFile) throws Exception {
        File tempFile = new File(targetFile.getAbsolutePath() + ".tmp");
        try (FileOutputStream fos = new FileOutputStream(tempFile)) {
            ks.store(fos, properties.getPassword().toCharArray());
            fos.flush();
        }
        Files.move(tempFile.toPath(), targetFile.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        log.info("💾 Flushed BCFKS keystore to disk ({} bytes)", targetFile.length());
    }

    private SSLContext buildSslContext(KeyStore ks) throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm(),
                BcfipsSecurityConfig.BCJSSE_PROVIDER_NAME
        );
        tmf.init(ks);

        SSLContext sslContext = SSLContext.getInstance("TLS", BcfipsSecurityConfig.BCJSSE_PROVIDER_NAME);
        sslContext.init(null, tmf.getTrustManagers(), null);
        return sslContext;
    }
}
