package com.example.proxygateway.ssl;

import com.example.proxygateway.model.HandshakeStage;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.Socket;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Educational Capturing Trust Manager.
 *
 * <p>Why X509ExtendedTrustManager?</p>
 * Standard {@link X509TrustManager} only receives {@code (X509Certificate[] chain, String authType)}.
 * Modern JSSE uses {@link X509ExtendedTrustManager}, which passes the active {@link Socket} or {@link SSLEngine}.
 * This allows hostname/SNI verification (endpoint identification algorithms like HTTPS).
 *
 * <p>How it Works:</p>
 * <ol>
 *   <li>Intercepts the TLS handshake before trust decisions are finalized.</li>
 *   <li>Records the entire presented peer certificate chain into {@link HandshakeCaptureContext}.</li>
 *   <li>Logs generous educational details about every certificate in the chain.</li>
 *   <li>Delegates validation to the underlying JSSE TrustManager (configured with current or ephemeral KeyStore).</li>
 *   <li>If validation succeeds, extracts the exact {@link TrustAnchor} used to validate the chain.</li>
 *   <li>If validation fails, analyzes the failure, pinpoints the missing Root CA / intermediate,
 *       and preserves it for the caller while securely aborting the connection.</li>
 * </ol>
 */
public class CapturingTrustManager extends X509ExtendedTrustManager {

    private final X509ExtendedTrustManager delegate;
    private final KeyStore activeKeyStore;
    private final HandshakeStage defaultStage;

    public CapturingTrustManager(X509ExtendedTrustManager delegate, KeyStore activeKeyStore, HandshakeStage defaultStage) {
        this.delegate = delegate;
        this.activeKeyStore = activeKeyStore;
        this.defaultStage = defaultStage;
    }

    public static CapturingTrustManager wrap(KeyStore keyStore, HandshakeStage defaultStage) {
        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keyStore);
            for (TrustManager tm : tmf.getTrustManagers()) {
                if (tm instanceof X509ExtendedTrustManager extended) {
                    return new CapturingTrustManager(extended, keyStore, defaultStage);
                } else if (tm instanceof X509TrustManager standard) {
                    return new CapturingTrustManager(new DelegatingExtendedTrustManager(standard), keyStore, defaultStage);
                }
            }
            throw new IllegalStateException("No X509TrustManager found in TrustManagerFactory");
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize CapturingTrustManager: " + e.getMessage(), e);
        }
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        captureAndVerify(chain, authType, socket != null ? socket.getInetAddress() + ":" + socket.getPort() : "unknown",
                () -> delegate.checkServerTrusted(chain, authType, socket));
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        captureAndVerify(chain, authType, engine != null ? engine.getPeerHost() + ":" + engine.getPeerPort() : "unknown",
                () -> delegate.checkServerTrusted(chain, authType, engine));
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        captureAndVerify(chain, authType, "standard-socket",
                () -> delegate.checkServerTrusted(chain, authType));
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        delegate.checkClientTrusted(chain, authType, socket);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        delegate.checkClientTrusted(chain, authType, engine);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        delegate.checkClientTrusted(chain, authType);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return delegate.getAcceptedIssuers();
    }

    private void captureAndVerify(X509Certificate[] chain, String authType, String peerInfo,
                                  ValidationAction action) throws CertificateException {
        HandshakeCaptureContext.CaptureState state = HandshakeCaptureContext.get();
        HandshakeStage stage = state.getCurrentStage() != HandshakeStage.NONE ? state.getCurrentStage() : defaultStage;

        LogCollector.log("🤝", "[TLS HANDSHAKE] Stage: {} | Peer: {} | AuthType: {}", stage, peerInfo, authType);

        if (chain == null || chain.length == 0) {
            LogCollector.error("Peer sent an empty certificate chain!");
            throw new CertificateException("No certificates received from peer during TLS handshake");
        }

        // Store captured chain in ThreadContext for this stage
        if (stage == HandshakeStage.PROXY_CONNECT_TLS) {
            state.setProxyChain(chain);
        } else {
            state.setTargetChain(chain);
        }

        // Educational logging of every certificate in the presented chain
        LogCollector.log("📜", "Peer presented {} certificate(s) in chain:", chain.length);
        for (int i = 0; i < chain.length; i++) {
            X509Certificate cert = chain[i];
            boolean selfSigned = CertificateInspector.isSelfSigned(cert);
            String role = (i == 0) ? "Leaf (Server)" : (i == chain.length - 1 && selfSigned ? "Root CA" : "Intermediate CA");
            LogCollector.log("   ", "├─ [{}] {}: Subject='{}' | Issuer='{}' | Serial={} | SelfSigned={}",
                    i, role, cert.getSubjectX500Principal().getName(),
                    cert.getIssuerX500Principal().getName(),
                    cert.getSerialNumber().toString(16), selfSigned);
            LogCollector.debug("   │  SHA-256 Fingerprint: {}", CertificateInspector.getSha256Fingerprint(cert));
            LogCollector.debug("   │  Validity: {} to {}", cert.getNotBefore(), cert.getNotAfter());
        }

        try {
            // Attempt standard JSSE validation via delegate
            LogCollector.log("🔎", "Validating certificate chain against active TrustStore...");
            action.run();

            // Handshake succeeded! Now extract the exact TrustAnchor used.
            LogCollector.log("✅", "TLS Handshake validation SUCCEEDED for stage {}", stage);
            resolveAndRecordTrustAnchor(chain, state);

        } catch (CertificateException ce) {
            LogCollector.warn("TLS Handshake validation FAILED: {}", ce.getMessage());
            state.setLastTlsException(ce);
            state.setFailedStage(stage);

            // Diagnose missing trust anchor
            diagnoseMissingAnchor(chain, state);

            // Re-throw to ensure secure termination of untrusted connection
            throw ce;
        }
    }

    /**
     * When validation succeeds, extracts the exact TrustAnchor from the KeyStore.
     */
    private void resolveAndRecordTrustAnchor(X509Certificate[] chain, HandshakeCaptureContext.CaptureState state) {
        try {
            X509Certificate topCert = chain[chain.length - 1];
            if (activeKeyStore != null) {
                var aliases = activeKeyStore.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    if (activeKeyStore.isCertificateEntry(alias)) {
                        X509Certificate anchorCert = (X509Certificate) activeKeyStore.getCertificate(alias);
                        if (!CertificateInspector.isSelfSigned(anchorCert)) {
                            continue;
                        }

                        boolean matches = false;
                        if (topCert.equals(anchorCert)) {
                            matches = true;
                        } else if (topCert.getIssuerX500Principal().equals(anchorCert.getSubjectX500Principal())) {
                            try {
                                topCert.verify(anchorCert.getPublicKey());
                                matches = true;
                            } catch (Exception ignored) {}
                        }

                        if (matches) {
                            TrustAnchor anchor = new TrustAnchor(anchorCert, null);
                            boolean fromCandidate = alias.startsWith("trial-candidate-ca-");

                            if (fromCandidate || state.getVerifiedTrustAnchor() == null) {
                                state.setVerifiedTrustAnchor(anchor);
                                state.setVerifiedAnchorAlias(alias);
                            }
                            if (fromCandidate) {
                                state.setAnchorFromCandidate(true);
                            }

                            LogCollector.log("🎯", "Isolated active TrustAnchor from In-Memory store: Subject='{}'",
                                    anchorCert.getSubjectX500Principal().getName());
                            LogCollector.log("   ", "Alias: '{}' | Source: {}", alias,
                                    fromCandidate ? "USER INPUT CANDIDATE (Required for connection!)" : "EXISTING PERSISTENT STORE");
                            return;
                        }
                    }
                }
            }
        } catch (Exception e) {
            LogCollector.warn("Could not isolate TrustAnchor: {}", e.getMessage());
        }
    }

    /**
     * When validation fails, pinpoints whether the root CA was presented or missing.
     */
    private void diagnoseMissingAnchor(X509Certificate[] chain, HandshakeCaptureContext.CaptureState state) {
        X509Certificate topCert = chain[chain.length - 1];
        boolean isTopSelfSigned = CertificateInspector.isSelfSigned(topCert);

        if (isTopSelfSigned) {
            LogCollector.log("💡", "[DIAGNOSIS] Peer presented its own Root CA in the chain: '{}'",
                    topCert.getSubjectX500Principal().getName());
            LogCollector.log("💡", "This Root CA is NOT in your trust store. Importing this Root CA will establish trust.");
            state.setMissingCertificate(topCert);
        } else {
            LogCollector.log("💡", "[DIAGNOSIS] Chain is incomplete. Top certificate is an intermediate: '{}'",
                    topCert.getSubjectX500Principal().getName());
            LogCollector.log("💡", "The Root CA that issued this intermediate is: '{}'",
                    topCert.getIssuerX500Principal().getName());
            LogCollector.log("💡", "To establish trust, you must import the Root CA for '{}'.",
                    topCert.getIssuerX500Principal().getName());
            state.setMissingCertificate(topCert);
        }
    }

    @FunctionalInterface
    private interface ValidationAction {
        void run() throws CertificateException;
    }

    /**
     * Fallback adapter for standard X509TrustManager to X509ExtendedTrustManager.
     */
    private static class DelegatingExtendedTrustManager extends X509ExtendedTrustManager {
        private final X509TrustManager delegate;

        DelegatingExtendedTrustManager(X509TrustManager delegate) {
            this.delegate = delegate;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
            delegate.checkClientTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
            delegate.checkServerTrusted(chain, authType);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
            delegate.checkClientTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
            delegate.checkServerTrusted(chain, authType);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            delegate.checkClientTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            delegate.checkServerTrusted(chain, authType);
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return delegate.getAcceptedIssuers();
        }
    }
}
