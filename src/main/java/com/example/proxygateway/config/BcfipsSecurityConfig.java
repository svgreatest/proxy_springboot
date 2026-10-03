package com.example.proxygateway.config;

import jakarta.annotation.PostConstruct;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.fips.FipsStatus;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;

import java.security.Provider;
import java.security.Security;
import java.util.Arrays;

/**
 * Educational BCFIPS Security Configuration.
 *
 * <p>Why BCFIPS?</p>
 * Standard Bouncy Castle (bcprov-jdk18on) is not FIPS 140-2/3 certified.
 * The Bouncy Castle FIPS module (bc-fips) is a certified cryptographic module that enforces:
 * <ul>
 *   <li>Only NIST-approved algorithms in FIPS mode (e.g., RSA >= 2048-bit, SHA-256+, AES-GCM).</li>
 *   <li>Power-on and conditional cryptographic self-tests (KAT - Known Answer Tests).</li>
 *   <li>Tamper-resistant KeyStore format: BCFKS (BC FIPS KeyStore).</li>
 * </ul>
 *
 * <p>Why BCJSSE?</p>
 * Standard SunJSSE might not default to BCFIPS for cipher suites and key management.
 * Registering BouncyCastleJsseProvider (bctls-fips) ensures TLS handshakes strictly utilize
 * FIPS-approved cipher suites and algorithms.
 */
@Configuration
public class BcfipsSecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(BcfipsSecurityConfig.class);

    public static final String BCFIPS_PROVIDER_NAME = "BCFIPS";
    public static final String BCJSSE_PROVIDER_NAME = "BCJSSE";

    @PostConstruct
    public void initFipsSecurityProviders() {
        log.info("================================================================================");
        log.info("🔐 [BCFIPS INIT] Initializing Bouncy Castle FIPS 140 Module & BCJSSE Provider");
        log.info("================================================================================");

        try {
            // 1. Install BCFIPS Cryptographic Provider at highest priority (Position 1)
            Provider currentBcfips = Security.getProvider(BCFIPS_PROVIDER_NAME);
            if (currentBcfips == null) {
                BouncyCastleFipsProvider bcfips = new BouncyCastleFipsProvider();
                int pos1 = Security.insertProviderAt(bcfips, 1);
                log.info("✅ Installed '{}' (version {}) at Security position {}",
                        bcfips.getName(), bcfips.getVersionStr(), pos1);
            } else {
                log.info("ℹ️ '{}' already registered at priority position.", currentBcfips.getName());
            }

            // 2. Install BCJSSE TLS Provider at position 2
            Provider currentBcJsse = Security.getProvider(BCJSSE_PROVIDER_NAME);
            if (currentBcJsse == null) {
                BouncyCastleJsseProvider bcjsse = new BouncyCastleJsseProvider();
                int pos2 = Security.insertProviderAt(bcjsse, 2);
                log.info("✅ Installed '{}' (version {}) at Security position {}",
                        bcjsse.getName(), bcjsse.getVersionStr(), pos2);
            } else {
                log.info("ℹ️ '{}' already registered at priority position.", currentBcJsse.getName());
            }

            // 3. Configure standard Java HttpClient for proxy tunneling authentication
            System.setProperty("jdk.http.auth.tunneling.disabledSchemes", "");
            System.setProperty("jdk.httpclient.allowRestrictedHeaders", "proxy-authorization");


            // 3. Inspect and log FIPS status
            boolean isFipsApproved = FipsStatus.isReady();
            log.info("🛡️ BCFIPS Self-Test Ready Status: {}", isFipsApproved ? "READY / APPROVED" : "NOT READY");
            log.info("🛡️ CryptoServicesRegistrar in approved mode: {}",
                    CryptoServicesRegistrar.isInApprovedOnlyMode());

            // 4. Log active security providers for transparency
            log.info("📜 Active Java Security Providers in JVM:");
            Provider[] providers = Security.getProviders();
            for (int i = 0; i < providers.length; i++) {
                log.info("    [{}] {} (v{}) - {}", i + 1, providers[i].getName(),
                        providers[i].getVersionStr(), providers[i].getInfo());
            }
            log.info("================================================================================");
        } catch (Exception e) {
            log.error("❌ CRITICAL: Failed to initialize BCFIPS / BCJSSE providers: {}", e.getMessage(), e);
            throw new IllegalStateException("BCFIPS initialization failed", e);
        }
    }
}
