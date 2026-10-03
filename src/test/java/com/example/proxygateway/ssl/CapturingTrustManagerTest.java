package com.example.proxygateway.ssl;

import com.example.proxygateway.config.BcfipsSecurityConfig;
import com.example.proxygateway.model.HandshakeStage;
import com.example.proxygateway.util.TestCertHelper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Educational Unit Test validating the behavior of CapturingTrustManager:
 * 1. Untrusted chain interception and capture.
 * 2. Missing Root CA diagnosis.
 * 3. Successful verification with In-Memory trust store.
 * 4. Active TrustAnchor isolation.
 */
class CapturingTrustManagerTest {

    @BeforeAll
    static void initSecurity() {
        new BcfipsSecurityConfig().initFipsSecurityProviders();
    }

    @BeforeEach
    void setUp() {
        LogCollector.start();
        HandshakeCaptureContext.clear();
    }

    @Test
    void testUntrustedChainCaptureAndDiagnosis() throws Exception {
        // 1. Generate an untrusted Root CA and Leaf
        TestCertHelper.KeyAndCert rootCa = TestCertHelper.generateRootCa("Untrusted Internal CA");
        TestCertHelper.KeyAndCert leaf = TestCertHelper.generateLeafCert("internal.corporate.local", rootCa);

        X509Certificate[] chain = new X509Certificate[]{leaf.certificate(), rootCa.certificate()};

        // 2. Create empty in-memory KeyStore
        KeyStore emptyKs = KeyStore.getInstance("BCFKS", BcfipsSecurityConfig.BCFIPS_PROVIDER_NAME);
        emptyKs.load(null, "pass".toCharArray());

        CapturingTrustManager ctm = CapturingTrustManager.wrap(emptyKs, HandshakeStage.TARGET_TLS);

        // 3. Verify that checkServerTrusted throws CertificateException
        CertificateException ex = assertThrows(CertificateException.class, () -> {
            ctm.checkServerTrusted(chain, "RSA");
        });

        // 4. Assert that the chain was captured in HandshakeCaptureContext
        HandshakeCaptureContext.CaptureState state = HandshakeCaptureContext.get();
        assertNotNull(state.getTargetChain(), "Presented chain should be captured");
        assertEquals(2, state.getTargetChain().length);
        assertEquals(leaf.certificate(), state.getTargetChain()[0]);

        // 5. Assert that the missing root CA was diagnosed correctly
        assertNotNull(state.getMissingCertificate(), "Missing CA should be identified");
        assertEquals(rootCa.certificate().getSubjectX500Principal(),
                state.getMissingCertificate().getSubjectX500Principal());
        assertTrue(CertificateInspector.isSelfSigned(state.getMissingCertificate()));

        // 6. Assert logs contain educational trace
        assertFalse(LogCollector.getLogs().isEmpty());
        assertTrue(LogCollector.getLogs().stream().anyMatch(line -> line.contains("Untrusted Internal CA")));
    }

    @Test
    void testSuccessfulHandshakeAndTrustAnchorIsolation() throws Exception {
        // 1. Generate Root CA and Leaf
        TestCertHelper.KeyAndCert rootCa = TestCertHelper.generateRootCa("Trusted Enterprise CA");
        TestCertHelper.KeyAndCert leaf = TestCertHelper.generateLeafCert("api.enterprise.com", rootCa);

        X509Certificate[] chain = new X509Certificate[]{leaf.certificate(), rootCa.certificate()};

        // 2. Create KeyStore containing ONLY the Root CA
        KeyStore ksWithRoot = KeyStore.getInstance("BCFKS", BcfipsSecurityConfig.BCFIPS_PROVIDER_NAME);
        ksWithRoot.load(null, "pass".toCharArray());
        ksWithRoot.setCertificateEntry("trusted-root-anchor", rootCa.certificate());

        CapturingTrustManager ctm = CapturingTrustManager.wrap(ksWithRoot, HandshakeStage.TARGET_TLS);

        // 3. Execution should succeed without exception (using FIPS-approved ECDHE_RSA authType)
        assertDoesNotThrow(() -> ctm.checkServerTrusted(chain, "ECDHE_RSA"));

        // 4. Assert that the active TrustAnchor was isolated
        HandshakeCaptureContext.CaptureState state = HandshakeCaptureContext.get();
        assertNotNull(state.getVerifiedTrustAnchor(), "Verified TrustAnchor must be isolated");
        assertEquals(rootCa.certificate().getSubjectX500Principal(),
                state.getVerifiedTrustAnchor().getTrustedCert().getSubjectX500Principal());

        // Ensure the leaf was NOT treated as the trust anchor
        assertNotEquals(leaf.certificate().getSubjectX500Principal(),
                state.getVerifiedTrustAnchor().getTrustedCert().getSubjectX500Principal());
    }

    @Test
    void testRejectNonRootOrIntermediateCertificate() throws Exception {
        TestCertHelper.KeyAndCert rootCa = TestCertHelper.generateRootCa("Test Root CA");
        TestCertHelper.KeyAndCert leaf = TestCertHelper.generateLeafCert("test.leaf.com", rootCa);

        // Root CA is self-signed: must pass
        assertDoesNotThrow(() -> CertificateInspector.validateRootCaOrSelfSigned(rootCa.certificate()));

        // Leaf / Intermediate is NOT self-signed: must be strictly rejected with IllegalArgumentException
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> {
            CertificateInspector.validateRootCaOrSelfSigned(leaf.certificate());
        });
        assertTrue(ex.getMessage().contains("Only Root CA or self-signed certificates"));
    }
}
