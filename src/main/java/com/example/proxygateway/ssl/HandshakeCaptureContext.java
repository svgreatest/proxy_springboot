package com.example.proxygateway.ssl;

import com.example.proxygateway.model.HandshakeStage;

import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Educational HandshakeCaptureContext.
 *
 * <p>Uses ThreadLocal to capture TLS handshake artifacts on the calling thread.
 * When Apache HttpClient 5 executes a request, it performs the TLS handshake on the
 * calling thread. The CapturingTrustManager writes the peer certificate chain,
 * validation outcome, and any missing/verified TrustAnchors here so the calling
 * service can inspect them.</p>
 */
public class HandshakeCaptureContext {

    public static class CaptureState {
        private HandshakeStage currentStage = HandshakeStage.NONE;
        private X509Certificate[] proxyChain;
        private X509Certificate[] targetChain;
        private X509Certificate missingCertificate;
        private TrustAnchor verifiedTrustAnchor;
        private Exception lastTlsException;
        private HandshakeStage failedStage;

        public HandshakeStage getCurrentStage() {
            return currentStage;
        }

        public void setCurrentStage(HandshakeStage currentStage) {
            this.currentStage = currentStage;
        }

        public X509Certificate[] getProxyChain() {
            return proxyChain;
        }

        public void setProxyChain(X509Certificate[] proxyChain) {
            this.proxyChain = proxyChain;
        }

        public X509Certificate[] getTargetChain() {
            return targetChain;
        }

        public void setTargetChain(X509Certificate[] targetChain) {
            this.targetChain = targetChain;
        }

        public X509Certificate getMissingCertificate() {
            return missingCertificate;
        }

        public void setMissingCertificate(X509Certificate missingCertificate) {
            this.missingCertificate = missingCertificate;
        }

        public TrustAnchor getVerifiedTrustAnchor() {
            return verifiedTrustAnchor;
        }

        public void setVerifiedTrustAnchor(TrustAnchor verifiedTrustAnchor) {
            this.verifiedTrustAnchor = verifiedTrustAnchor;
        }

        private String verifiedAnchorAlias;
        private boolean anchorFromCandidate;

        public String getVerifiedAnchorAlias() {
            return verifiedAnchorAlias;
        }

        public void setVerifiedAnchorAlias(String verifiedAnchorAlias) {
            this.verifiedAnchorAlias = verifiedAnchorAlias;
        }

        public boolean isAnchorFromCandidate() {
            return anchorFromCandidate;
        }

        public void setAnchorFromCandidate(boolean anchorFromCandidate) {
            this.anchorFromCandidate = anchorFromCandidate;
        }

        public Exception getLastTlsException() {
            return lastTlsException;
        }

        public void setLastTlsException(Exception lastTlsException) {
            this.lastTlsException = lastTlsException;
        }

        public HandshakeStage getFailedStage() {
            return failedStage;
        }

        public void setFailedStage(HandshakeStage failedStage) {
            this.failedStage = failedStage;
        }
    }

    private static final ThreadLocal<CaptureState> THREAD_CONTEXT = ThreadLocal.withInitial(CaptureState::new);
    private static final AtomicReference<CaptureState> ACTIVE_SESSION = new AtomicReference<>();

    public static void startSession(CaptureState state) {
        ACTIVE_SESSION.set(state);
        THREAD_CONTEXT.set(state);
    }

    public static CaptureState get() {
        CaptureState session = ACTIVE_SESSION.get();
        if (session != null) {
            return session;
        }
        return THREAD_CONTEXT.get();
    }

    public static void initStage(HandshakeStage stage) {
        get().setCurrentStage(stage);
    }

    public static void clear() {
        ACTIVE_SESSION.set(null);
        THREAD_CONTEXT.remove();
    }
}
