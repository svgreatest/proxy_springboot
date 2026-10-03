package com.example.proxygateway.ssl;

import com.example.proxygateway.config.BcfipsSecurityConfig;
import com.example.proxygateway.model.HandshakeStage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;

/**
 * Educational In-Memory Trust Store Manager.
 *
 * <p>Why In-Memory Trust Management?</p>
 * During connection testing or troubleshooting, an administrator may provide a candidate Root CA.
 * If the application immediately wrote this candidate CA to its master trust store, an attacker
 * or misconfigured user could poison the application's root of trust or cause concurrency issues
 * with other production requests.
 *
 * <p>Instead, this manager builds an <b>ephemeral, isolated in-memory KeyStore</b>:</p>
 * <ol>
 *   <li>Copies current trusted anchors from {@link PersistentTrustStoreService}.</li>
 *   <li>If candidate Root CA PEM is provided, imports it <i>only</i> into this transient in-memory store.</li>
 *   <li>Creates an isolated {@link SSLContext} powered by BCJSSE and {@link CapturingTrustManager}.</li>
 *   <li>If the connection fails, the ephemeral store is simply garbage-collected. The disk store is untouched.</li>
 * </ol>
 */
@Service
public class InMemoryTrustStoreManager {

    private static final Logger log = LoggerFactory.getLogger(InMemoryTrustStoreManager.class);

    private final PersistentTrustStoreService persistentTrustStoreService;

    public InMemoryTrustStoreManager(PersistentTrustStoreService persistentTrustStoreService) {
        this.persistentTrustStoreService = persistentTrustStoreService;
    }

    public record EphemeralSslBundle(
            SSLContext sslContext,
            KeyStore keyStore,
            CapturingTrustManager capturingTrustManager
    ) {}

    /**
     * Builds an isolated, ephemeral SSLContext bundle for a single probe session.
     *
     * @param candidateRootPem optional candidate Root CA PEM provided by the user in Step 2.
     * @param defaultStage the TLS stage to associate with this bundle.
     * @return EphemeralSslBundle containing the SSLContext and CapturingTrustManager.
     */
    public EphemeralSslBundle createEphemeralBundle(String candidateRootPem, HandshakeStage defaultStage) {
        try {
            LogCollector.log("🧪", "[IN-MEMORY TRUST STORE] Creating ephemeral BCFKS keystore for probe session");

            // 1. Initialize empty in-memory BCFKS KeyStore
            KeyStore ephemeralKs = KeyStore.getInstance("BCFKS", BcfipsSecurityConfig.BCFIPS_PROVIDER_NAME);
            ephemeralKs.load(null, "ephemeral-probe-password".toCharArray());

            // 2. Clone active anchors from persistent master store
            KeyStore masterKs = persistentTrustStoreService.getMasterKeyStore();
            Enumeration<String> aliases = masterKs.aliases();
            int clonedCount = 0;
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (masterKs.isCertificateEntry(alias)) {
                    ephemeralKs.setCertificateEntry(alias, masterKs.getCertificate(alias));
                    clonedCount++;
                }
            }
            LogCollector.log("📋", "Copied {} existing trust anchors from master store into ephemeral store", clonedCount);

            // 3. Inject candidate Root CA if provided
            if (candidateRootPem != null && !candidateRootPem.trim().isEmpty()) {
                List<X509Certificate> candidates = CertificateInspector.parsePemCertificates(candidateRootPem);
                LogCollector.log("📥", "Parsing candidate Root CA PEM: found {} certificate(s)", candidates.size());

                for (int i = 0; i < candidates.size(); i++) {
                    X509Certificate candidate = candidates.get(i);
                    // STRICT VALIDATION: Ensure candidate is a Root CA or self-signed cert
                    CertificateInspector.validateRootCaOrSelfSigned(candidate);

                    String trialAlias = "trial-candidate-ca-" + (i + 1);
                    ephemeralKs.setCertificateEntry(trialAlias, candidate);

                    LogCollector.log("✨", "Injected candidate Root CA [{}] into EPHEMERAL store under alias '{}'", i + 1, trialAlias);
                    LogCollector.log("   ", "Subject: '{}'", candidate.getSubjectX500Principal().getName());
                    LogCollector.log("   ", "Issuer:  '{}'", candidate.getIssuerX500Principal().getName());
                    LogCollector.log("   ", "Self-Signed: {}", CertificateInspector.isSelfSigned(candidate));
                    LogCollector.log("   ", "SHA-256: {}", CertificateInspector.getSha256Fingerprint(candidate));
                }
            } else {
                LogCollector.log("ℹ️", "No candidate Root CA provided. Probing using only existing persistent anchors.");
            }

            // 4. Wrap with CapturingTrustManager
            CapturingTrustManager capturingTm = CapturingTrustManager.wrap(ephemeralKs, defaultStage);

            // 5. Build isolated SSLContext using BCJSSE
            SSLContext ephemeralSslContext = SSLContext.getInstance("TLS", BcfipsSecurityConfig.BCJSSE_PROVIDER_NAME);
            ephemeralSslContext.init(null, new TrustManager[]{capturingTm}, null);

            LogCollector.log("🛡️", "Ephemeral SSLContext successfully initialized with BCJSSE & CapturingTrustManager");

            return new EphemeralSslBundle(ephemeralSslContext, ephemeralKs, capturingTm);

        } catch (Exception e) {
            LogCollector.error("Failed to construct ephemeral in-memory trust store: {}", e.getMessage());
            throw new RuntimeException("Ephemeral trust store creation failed: " + e.getMessage(), e);
        }
    }
}
