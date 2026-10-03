package com.example.proxygateway.service;

import com.example.proxygateway.client.ProxyHttpClientFactory;
import com.example.proxygateway.config.BcfipsSecurityConfig;
import com.example.proxygateway.config.TrustStoreProperties;
import com.example.proxygateway.model.*;
import com.example.proxygateway.ssl.CertificateInspector;
import com.example.proxygateway.ssl.InMemoryTrustStoreManager;
import com.example.proxygateway.ssl.PersistentTrustStoreService;
import com.example.proxygateway.util.MockProxyServer;
import com.example.proxygateway.util.TestCertHelper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Educational Integration Test validating the full 2-Step Proxy Connectivity lifecycle:
 *
 * 1. Plain HTTP Proxy routing.
 * 2. Authenticated HTTP Proxy (407 challenge and resolution).
 * 3. MITM Inspection Proxy:
 *    - Step 1: Untrusted root capture & diagnosis (store left untouched).
 *    - Step 2: In-memory verification with candidate Root CA.
 *    - Step 3: Anchor commitment to persistent BCFKS store & subsequent trusted access.
 */
class ProxyProbeServiceTest {

    @TempDir
    Path tempDir;

    private PersistentTrustStoreService persistentTrustStoreService;
    private InMemoryTrustStoreManager inMemoryTrustStoreManager;
    private ProxyHttpClientFactory httpClientFactory;
    private ProxyProbeService probeService;

    private MockProxyServer proxyServer;

    @BeforeAll
    static void initSecurity() {
        new BcfipsSecurityConfig().initFipsSecurityProviders();
    }

    @BeforeEach
    void setUp() {
        TrustStoreProperties props = new TrustStoreProperties();
        props.setPath(tempDir.resolve("test-truststore.bcfks").toString());
        props.setPassword("test-bcfips-password-2026");

        persistentTrustStoreService = new PersistentTrustStoreService(props);
        persistentTrustStoreService.init();

        inMemoryTrustStoreManager = new InMemoryTrustStoreManager(persistentTrustStoreService);
        httpClientFactory = new ProxyHttpClientFactory();
        probeService = new ProxyProbeService(inMemoryTrustStoreManager, persistentTrustStoreService, httpClientFactory);
    }

    @AfterEach
    void tearDown() {
        if (proxyServer != null) {
            proxyServer.close();
        }
    }

    @Test
    void testPlainHttpProxyConnection() throws Exception {
        proxyServer = MockProxyServer.createPlain(0);
        proxyServer.start();

        ProxyConfig proxyConfig = new ProxyConfig("127.0.0.1", proxyServer.getPort(), ProxyProtocol.HTTP);
        ProbeRequest request = new ProbeRequest("http://127.0.0.1/test", proxyConfig);

        ProbeResponse response = probeService.probe(request);

        assertEquals(ProbeStatus.SUCCESS, response.getStatus());
        assertEquals(200, response.getHttpStatusCode());
        assertFalse(response.getDiagnosticLogs().isEmpty());
    }

    @Test
    void testAuthenticatedHttpProxyChallengeAndSuccess() throws Exception {
        proxyServer = MockProxyServer.createWithAuth(0, "testuser", "testpass");
        proxyServer.start();

        // 1. Probe with NO credentials -> Expect 407 FAILED_PROXY_AUTH
        ProxyConfig unauthConfig = new ProxyConfig("127.0.0.1", proxyServer.getPort(), ProxyProtocol.HTTP);
        ProbeRequest req1 = new ProbeRequest("http://127.0.0.1/test", unauthConfig);
        ProbeResponse resp1 = probeService.probe(req1);

        assertEquals(ProbeStatus.FAILED_PROXY_AUTH, resp1.getStatus());
        assertTrue(resp1.getMessage().contains("407"));

        // 2. Probe WITH correct credentials -> Expect SUCCESS
        ProxyConfig authConfig = new ProxyConfig("127.0.0.1", proxyServer.getPort(), ProxyProtocol.HTTP, "testuser", "testpass");
        ProbeRequest req2 = new ProbeRequest("http://127.0.0.1/test", authConfig);
        ProbeResponse resp2 = probeService.probe(req2);

        assertEquals(ProbeStatus.SUCCESS, resp2.getStatus());
        assertEquals(200, resp2.getHttpStatusCode());
    }

    @Test
    void testTwoStepConnectivityWorkflowWithMitmInspection() throws Exception {
        // 1. Generate MITM Root CA
        TestCertHelper.KeyAndCert mitmRootCa = TestCertHelper.generateRootCa("Corporate MITM Inspection CA");
        String mitmRootPem = CertificateInspector.toPem(mitmRootCa.certificate());

        proxyServer = MockProxyServer.createMitm(0, mitmRootCa);
        proxyServer.start();

        ProxyConfig proxyConfig = new ProxyConfig("127.0.0.1", proxyServer.getPort(), ProxyProtocol.HTTP);
        String targetHttpsUrl = "https://127.0.0.1:" + proxyServer.getPort() + "/secure-data";

        int initialStoreCount = persistentTrustStoreService.listEntries().size();

        // =========================================================================
        // STEP 1: Probe WITHOUT Root CA
        // =========================================================================
        ProbeRequest step1Req = new ProbeRequest(targetHttpsUrl, proxyConfig);
        ProbeResponse step1Resp = probeService.probe(step1Req);

        // Assert failure due to untrusted root
        assertEquals(ProbeStatus.FAILED_UNTRUSTED_ROOT, step1Resp.getStatus());
        assertNotNull(step1Resp.getMissingTrustAnchor(), "Should identify missing root CA");
        assertEquals(mitmRootCa.certificate().getSubjectX500Principal().getName(),
                step1Resp.getMissingTrustAnchor().getSubjectDn());

        // CRITICAL INVARIANT: The persistent trust store MUST REMAIN UNTOUCHED!
        assertEquals(initialStoreCount, persistentTrustStoreService.listEntries().size(),
                "Persistent trust store must remain completely untouched on failure");

        // =========================================================================
        // STEP 2: Verify in Ephemeral In-Memory Store using Candidate Root CA PEM
        // =========================================================================
        ProbeRequest step2Req = new ProbeRequest(targetHttpsUrl, proxyConfig, mitmRootPem);
        ProbeResponse step2Resp = probeService.probe(step2Req);

        assertEquals(ProbeStatus.SUCCESS, step2Resp.getStatus());
        assertEquals(200, step2Resp.getHttpStatusCode());
        assertNotNull(step2Resp.getVerifiedTrustAnchor(), "Should isolate verified TrustAnchor");

        // The persistent trust store is STILL untouched until explicitly committed
        assertEquals(initialStoreCount, persistentTrustStoreService.listEntries().size(),
                "Persistent trust store must remain untouched before commit");

        // =========================================================================
        // STEP 3: Commit Verified Root CA to Persistent BCFKS Store
        // =========================================================================
        CommitRequest commitReq = new CommitRequest(mitmRootPem, "mitm-test-ca");
        CommitResponse commitResp = probeService.commitRootCa(commitReq);

        assertTrue(commitResp.isSuccess());
        assertEquals("mitm-test-ca", commitResp.getAlias());

        // Verify it is now in the persistent store
        List<TrustStoreEntry> updatedEntries = persistentTrustStoreService.listEntries();
        assertEquals(initialStoreCount + 1, updatedEntries.size());
        assertTrue(updatedEntries.stream().anyMatch(e -> "mitm-test-ca".equals(e.getAlias())));

        // =========================================================================
        // STEP 4: Subsequent Probe without candidate PEM now succeeds persistently!
        // =========================================================================
        ProbeRequest step4Req = new ProbeRequest(targetHttpsUrl, proxyConfig);
        ProbeResponse step4Resp = probeService.probe(step4Req);

        assertEquals(ProbeStatus.SUCCESS, step4Resp.getStatus());
        assertEquals(200, step4Resp.getHttpStatusCode());
    }

    @Test
    void testTrustStoreEntryDetailInspection() throws Exception {
        TestCertHelper.KeyAndCert testRoot = TestCertHelper.generateRootCa("Inspect Root CA");
        String testRootPem = CertificateInspector.toPem(testRoot.certificate());
        CommitResponse commitResp = probeService.commitRootCa(new CommitRequest(testRootPem, "inspect-root-ca"));
        assertTrue(commitResp.isSuccess());

        CertificateDetail detail = probeService.getTrustStoreEntryDetail("inspect-root-ca");
        assertNotNull(detail, "Detail should be found for committed root CA");
        assertEquals("inspect-root-ca", detail.getAlias());
        assertTrue(detail.isSelfSigned(), "Committed Root CA must be self-signed");
        assertEquals("RSA", detail.getKeyAlgorithm());
        assertEquals(2048, detail.getKeySize());
        assertNotNull(detail.getSha1Fingerprint());
        assertNotNull(detail.getSha256Fingerprint());
        assertTrue(detail.getBasicConstraints().contains("CA=true"));
        assertNotNull(detail.getEducationalExplanation());
        assertTrue(detail.getEducationalExplanation().contains("Root Certificate Authority"));
        assertNotNull(detail.getPem());
    }

    @Test
    void testHttpsForwardProxyWhenContainerRunning() {
        try (java.net.Socket s = new java.net.Socket()) {
            s.connect(new java.net.InetSocketAddress("127.0.0.1", 8443), 1000);
        } catch (Exception e) {
            // Container not running in this environment, skip gracefully
            return;
        }

        ProxyConfig proxy = new ProxyConfig("127.0.0.1", 8443, ProxyProtocol.HTTPS, "testuser", "testpass");

        // 1. Without candidate CA, probe should capture the untrusted proxy certificate in PROXY_CONNECT_TLS stage!
        ProbeRequest req1 = new ProbeRequest("https://httpbin.org/get", proxy);
        ProbeResponse resp1 = probeService.probe(req1);

        assertEquals(ProbeStatus.FAILED_UNTRUSTED_PROXY, resp1.getStatus());
        assertNotNull(resp1.getMissingTrustAnchor());
        assertEquals(HandshakeStage.PROXY_CONNECT_TLS, resp1.getHandshakeStage());
        assertTrue(resp1.getMissingTrustAnchor().getSubjectDn().contains("127.0.0.1"));

        // 2. With the proxy certificate provided as candidate, probe should SUCCEED!
        String proxyCertPem = resp1.getMissingTrustAnchor().getPem();
        ProbeRequest req2 = new ProbeRequest("https://httpbin.org/get", proxy, proxyCertPem);
        ProbeResponse resp2 = probeService.probe(req2);

        assertEquals(ProbeStatus.SUCCESS, resp2.getStatus());
        assertEquals(200, resp2.getHttpStatusCode());
        assertTrue(resp2.isAnchorFromCandidateInput());
    }
}
