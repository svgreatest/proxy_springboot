package com.example.proxygateway.service;

import com.example.proxygateway.client.ProxyHttpClientFactory;
import com.example.proxygateway.model.CertificateDetail;
import com.example.proxygateway.model.CommitRequest;
import com.example.proxygateway.model.CommitResponse;
import com.example.proxygateway.model.HandshakeStage;
import com.example.proxygateway.model.ProbeRequest;
import com.example.proxygateway.model.ProbeResponse;
import com.example.proxygateway.model.ProbeStatus;
import com.example.proxygateway.model.ProxyProtocol;
import com.example.proxygateway.model.TrustStoreEntry;
import com.example.proxygateway.ssl.CertificateInspector;
import com.example.proxygateway.ssl.HandshakeCaptureContext;
import com.example.proxygateway.ssl.InMemoryTrustStoreManager;
import com.example.proxygateway.ssl.LogCollector;
import com.example.proxygateway.ssl.PersistentTrustStoreService;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.io.support.ClassicRequestBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Educational Service orchestrating the 2-step proxy connectivity workflow:
 *
 * <ol>
 *   <li>Step 1 (Probe): Probes target website via proxy using an ephemeral In-Memory TrustStore.
 *       Captures presented certificates and diagnoses missing Root CAs without mutating persistent store.</li>
 *   <li>Step 2 (Verify & Commit): Tests candidate Root CA in memory. Only upon verified success
 *       does it commit the active TrustAnchor to the persistent BCFKS store.</li>
 * </ol>
 */
@Service
public class ProxyProbeService {

    private static final Logger log = LoggerFactory.getLogger(ProxyProbeService.class);

    private final InMemoryTrustStoreManager inMemoryTrustStoreManager;
    private final PersistentTrustStoreService persistentTrustStoreService;
    private final ProxyHttpClientFactory httpClientFactory;

    public ProxyProbeService(InMemoryTrustStoreManager inMemoryTrustStoreManager,
                             PersistentTrustStoreService persistentTrustStoreService,
                             ProxyHttpClientFactory httpClientFactory) {
        this.inMemoryTrustStoreManager = inMemoryTrustStoreManager;
        this.persistentTrustStoreService = persistentTrustStoreService;
        this.httpClientFactory = httpClientFactory;
    }

    /**
     * Probes target URL through proxy in an isolated ephemeral environment.
     */
    public ProbeResponse probe(ProbeRequest request) {
        LogCollector.start();
        HandshakeCaptureContext.clear();
        HandshakeCaptureContext.startSession(new HandshakeCaptureContext.CaptureState());

        LogCollector.log("🚀", "Starting Proxy Probe Request: Target='{}' via Proxy='{}'",
                request.getTargetUrl(), request.getProxy());

        HandshakeStage initialStage = (request.getProxy().getProtocol() == ProxyProtocol.HTTPS)
                ? HandshakeStage.PROXY_CONNECT_TLS
                : HandshakeStage.TARGET_TLS;

        HandshakeCaptureContext.initStage(initialStage);

        try {
            // 1. Build Ephemeral In-Memory SSL Bundle (keeps persistent store untouched!)
            var bundle = inMemoryTrustStoreManager.createEphemeralBundle(
                    request.getCandidateRootPem(),
                    initialStage
            );

            // 2. Build Apache HttpClient 5 with multi-stage TLS & proxy routing
            CloseableHttpClient httpClient = httpClientFactory.createClient(request.getProxy(), bundle.sslContext());

            ClassicHttpRequest httpRequest = ClassicRequestBuilder.get(request.getTargetUrl())
                    .setHeader("User-Agent", "Mozilla/5.0 (ProxyGateway-BCFIPS-JSSE; Apache-HC5)")
                    .build();

            LogCollector.log("📡", "Executing HTTP GET request to '{}'...", request.getTargetUrl());

            try (CloseableHttpResponse response = httpClient.execute(httpRequest)) {
                int statusCode = response.getCode();
                LogCollector.log("📥", "Received HTTP Response: {}", statusCode);

                // Check for 407 Proxy Authentication Required
                if (statusCode == 407) {
                    LogCollector.error("Proxy returned 407: Proxy Authentication Required!");
                    return ProbeResponse.failed(
                            ProbeStatus.FAILED_PROXY_AUTH,
                            HandshakeStage.NONE,
                            request.getTargetUrl(),
                            "Proxy authentication failed (HTTP 407). Please verify username/password.",
                            getCapturedChainDetails(),
                            null,
                            LogCollector.getLogs()
                    );
                }

                // Handshake and HTTP exchange succeeded!
                LogCollector.log("🎉", "SUCCESS! Connection established and validated through proxy.");
                HandshakeCaptureContext.CaptureState state = HandshakeCaptureContext.get();
                boolean anchorFromCandidate = state.isAnchorFromCandidate();
                CertificateDetail verifiedAnchor = extractVerifiedAnchor(request.getCandidateRootPem());

                if (request.getCandidateRootPem() != null && !request.getCandidateRootPem().trim().isEmpty()) {
                    if (anchorFromCandidate) {
                        LogCollector.log("⭐", "[IN-MEMORY ANCHOR ISOLATION] The candidate Root CA was REQUIRED and verified the connection!");
                    } else {
                        LogCollector.log("ℹ️", "[IN-MEMORY ANCHOR ISOLATION] Candidate Root CA was NOT required. The connection was already anchored by: '{}'.",
                                state.getVerifiedAnchorAlias());
                    }
                }

                return ProbeResponse.success(
                        statusCode,
                        request.getTargetUrl(),
                        "Connection successfully established! Response: HTTP " + statusCode,
                        getCapturedChainDetails(),
                        verifiedAnchor,
                        anchorFromCandidate,
                        LogCollector.getLogs()
                );
            }

        } catch (Exception e) {
            return handleProbeException(e, request);
        } finally {
            LogCollector.debug("Probe execution finished. Ephemeral context discarded.");
        }
    }

    /**
     * Commits the verified Root CA to the persistent BCFKS keystore.
     */
    public CommitResponse commitRootCa(CommitRequest request) {
        try {
            X509Certificate cert = CertificateInspector.parseSinglePem(request.getRootPem());

            // STRICT VALIDATION: Certificate must be a Root CA or self-signed certificate!
            CertificateInspector.validateRootCaOrSelfSigned(cert);

            TrustStoreEntry entry = persistentTrustStoreService.commitTrustAnchor(cert, request.getAlias());

            return new CommitResponse(
                    true,
                    entry.getAlias(),
                    entry.getSubjectDn(),
                    entry.getSha256Fingerprint(),
                    "Root CA successfully committed to persistent BCFKS trust store!"
            );
        } catch (Exception e) {
            log.error("Commit failed: {}", e.getMessage(), e);
            return new CommitResponse(false, null, null, null, "Failed to commit Root CA: " + e.getMessage());
        }
    }

    public List<TrustStoreEntry> listTrustStoreEntries() {
        return persistentTrustStoreService.listEntries();
    }

    public CertificateDetail getTrustStoreEntryDetail(String alias) {
        return persistentTrustStoreService.getEntryDetail(alias);
    }

    public boolean deleteTrustStoreEntry(String alias) {
        return persistentTrustStoreService.deleteTrustAnchor(alias);
    }

    private ProbeResponse handleProbeException(Exception e, ProbeRequest request) {
        LogCollector.error("Probe encountered exception: {}", e.getMessage());

        HandshakeCaptureContext.CaptureState state = HandshakeCaptureContext.get();
        List<CertificateDetail> chain = getCapturedChainDetails();
        CertificateDetail missingAnchor = null;

        if (state.getMissingCertificate() != null) {
            missingAnchor = CertificateInspector.toDetail(state.getMissingCertificate());
        }

        // Check if SSL handshake failure occurred
        if (isSslException(e) || state.getLastTlsException() != null) {
            HandshakeStage failedStage = state.getFailedStage() != null ? state.getFailedStage() : state.getCurrentStage();
            ProbeStatus status = (failedStage == HandshakeStage.PROXY_CONNECT_TLS)
                    ? ProbeStatus.FAILED_UNTRUSTED_PROXY
                    : ProbeStatus.FAILED_UNTRUSTED_ROOT;

            String explanation;
            if (failedStage == HandshakeStage.PROXY_CONNECT_TLS) {
                explanation = "Direct TLS connection to the HTTPS proxy server failed because its certificate is untrusted.";
            } else if (missingAnchor != null && missingAnchor.isSelfSigned()) {
                explanation = "Target/Inspection proxy presented an untrusted Root CA: [" + missingAnchor.getSubjectDn() + "]. Add this Root CA to proceed.";
            } else if (missingAnchor != null) {
                explanation = "Incomplete certificate chain. Intermediate certificate presented: [" + missingAnchor.getSubjectDn() + "] issued by missing Root CA: [" + missingAnchor.getIssuerDn() + "]. Please provide the Root CA.";
            } else {
                explanation = "TLS handshake failed: untrusted certificate path. " + e.getMessage();
            }

            LogCollector.log("💡", "Actionable Guidance: {}", explanation);

            return ProbeResponse.failed(
                    status,
                    failedStage,
                    request.getTargetUrl(),
                    explanation,
                    chain,
                    missingAnchor,
                    LogCollector.getLogs()
            );
        }

        // Check for 407 Proxy Authentication Required in exception message (e.g. Java HttpClient tunneling failure)
        if (e.getMessage() != null && e.getMessage().contains("407")) {
            String msg = "Proxy authentication failed (HTTP 407). Please verify username/password.";
            LogCollector.error(msg);
            return ProbeResponse.failed(
                    ProbeStatus.FAILED_PROXY_AUTH,
                    HandshakeStage.NONE,
                    request.getTargetUrl(),
                    msg,
                    chain,
                    null,
                    LogCollector.getLogs()
            );
        }

        // Check for HTTP 501 Not Implemented (pointing to Spring Boot / standard web server instead of a proxy)
        if (e.getMessage() != null && e.getMessage().contains("501")) {
            String msg = "Proxy CONNECT returned HTTP 501 (Not Implemented). The endpoint " +
                    request.getProxy().getHost() + ":" + request.getProxy().getPort() +
                    " is an application web server (e.g. Tomcat on port 8080) rather than a proxy server. " +
                    "For mitmproxy, please use port 8888. For Squid, use port 3128 or 3129.";
            LogCollector.warn(msg);
            return ProbeResponse.failed(
                    ProbeStatus.FAILED_CONNECTION,
                    HandshakeStage.NONE,
                    request.getTargetUrl(),
                    msg,
                    chain,
                    null,
                    LogCollector.getLogs()
            );
        }

        // Check for Protocol Mismatch: Client attempted TLS to a cleartext HTTP proxy port (72 is ASCII 'H' for HTTP)
        if (e.getMessage() != null && (e.getMessage().contains("UNKNOWN(72)") || e.getMessage().contains("Unsupported UNKNOWN(72)"))) {
            String msg = "Protocol Mismatch: You selected 'HTTPS Proxy (TLS)', but the proxy server at " +
                    request.getProxy().getHost() + ":" + request.getProxy().getPort() +
                    " is listening on cleartext HTTP (it responded with 'H' for HTTP/1.1 instead of TLS handshake). " +
                    "Please switch Proxy Protocol from 'HTTPS' to 'HTTP'.";
            LogCollector.warn(msg);
            return ProbeResponse.failed(
                    ProbeStatus.FAILED_CONNECTION,
                    HandshakeStage.PROXY_CONNECT_TLS,
                    request.getTargetUrl(),
                    msg,
                    chain,
                    null,
                    LogCollector.getLogs()
            );
        }

        // Generic I/O or network failure
        return ProbeResponse.failed(
                ProbeStatus.FAILED_CONNECTION,
                HandshakeStage.NONE,
                request.getTargetUrl(),
                "Connection failed: " + e.getMessage(),
                chain,
                null,
                LogCollector.getLogs()
        );
    }

    private List<CertificateDetail> getCapturedChainDetails() {
        HandshakeCaptureContext.CaptureState state = HandshakeCaptureContext.get();
        X509Certificate[] certs = state.getTargetChain();
        if (certs == null || certs.length == 0) {
            certs = state.getProxyChain();
        }
        if (certs == null) {
            return new ArrayList<>();
        }
        return Arrays.stream(certs)
                .map(CertificateInspector::toDetail)
                .toList();
    }

    private CertificateDetail extractVerifiedAnchor(String candidateRootPem) {
        HandshakeCaptureContext.CaptureState state = HandshakeCaptureContext.get();
        if (state.getVerifiedTrustAnchor() != null) {
            return CertificateInspector.toDetail(state.getVerifiedTrustAnchor().getTrustedCert());
        }
        return null;
    }

    private boolean isSslException(Throwable t) {
        while (t != null) {
            if (t instanceof SSLException || t instanceof CertificateException) {
                return true;
            }
            t = t.getCause();
        }
        return false;
    }
}
