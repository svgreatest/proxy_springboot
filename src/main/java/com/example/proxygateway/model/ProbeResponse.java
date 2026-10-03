package com.example.proxygateway.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Result returned to the client and UI after probing a proxy connection.
 */
public class ProbeResponse {

    private ProbeStatus status;
    private int httpStatusCode;
    private HandshakeStage handshakeStage;
    private String targetUrl;
    private String message;

    /**
     * Complete certificate chain captured by the CapturingTrustManager during the TLS handshake.
     * Ordered from Leaf (index 0) to Intermediate(s) to Root (if presented).
     */
    private List<CertificateDetail> capturedChain = new ArrayList<>();

    /**
     * If validation failed due to missing root/intermediate anchor, this field
     * details the missing certificate that needs to be imported.
     */
    private CertificateDetail missingTrustAnchor;

    /**
     * Active TrustAnchor extracted from PKIXCertPathValidatorResult if validation succeeded.
     */
    private CertificateDetail verifiedTrustAnchor;

    /**
     * True if the verified TrustAnchor came from user candidate input (meaning it was REQUIRED and must be saved).
     * False if the connection succeeded using an already-existing persistent/system root.
     */
    private boolean anchorFromCandidateInput;

    /**
     * Rich diagnostic logs generated during this probe for educational visibility.
     */
    private List<String> diagnosticLogs = new ArrayList<>();

    public ProbeResponse() {}

    public static ProbeResponse success(int httpStatusCode, String targetUrl, String message,
                                        List<CertificateDetail> chain, CertificateDetail verifiedTrustAnchor,
                                        boolean anchorFromCandidateInput, List<String> logs) {
        ProbeResponse response = new ProbeResponse();
        response.setStatus(ProbeStatus.SUCCESS);
        response.setHttpStatusCode(httpStatusCode);
        response.setHandshakeStage(HandshakeStage.NONE);
        response.setTargetUrl(targetUrl);
        response.setMessage(message);
        response.setCapturedChain(chain != null ? chain : new ArrayList<>());
        response.setVerifiedTrustAnchor(verifiedTrustAnchor);
        response.setAnchorFromCandidateInput(anchorFromCandidateInput);
        response.setDiagnosticLogs(logs != null ? logs : new ArrayList<>());
        return response;
    }

    public static ProbeResponse failed(ProbeStatus status, HandshakeStage stage, String targetUrl,
                                       String message, List<CertificateDetail> chain,
                                       CertificateDetail missingTrustAnchor, List<String> logs) {
        ProbeResponse response = new ProbeResponse();
        response.setStatus(status);
        response.setHandshakeStage(stage);
        response.setTargetUrl(targetUrl);
        response.setMessage(message);
        response.setCapturedChain(chain != null ? chain : new ArrayList<>());
        response.setMissingTrustAnchor(missingTrustAnchor);
        response.setDiagnosticLogs(logs != null ? logs : new ArrayList<>());
        return response;
    }

    public ProbeStatus getStatus() {
        return status;
    }

    public void setStatus(ProbeStatus status) {
        this.status = status;
    }

    public int getHttpStatusCode() {
        return httpStatusCode;
    }

    public void setHttpStatusCode(int httpStatusCode) {
        this.httpStatusCode = httpStatusCode;
    }

    public HandshakeStage getHandshakeStage() {
        return handshakeStage;
    }

    public void setHandshakeStage(HandshakeStage handshakeStage) {
        this.handshakeStage = handshakeStage;
    }

    public String getTargetUrl() {
        return targetUrl;
    }

    public void setTargetUrl(String targetUrl) {
        this.targetUrl = targetUrl;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public List<CertificateDetail> getCapturedChain() {
        return capturedChain;
    }

    public void setCapturedChain(List<CertificateDetail> capturedChain) {
        this.capturedChain = capturedChain;
    }

    public CertificateDetail getMissingTrustAnchor() {
        return missingTrustAnchor;
    }

    public void setMissingTrustAnchor(CertificateDetail missingTrustAnchor) {
        this.missingTrustAnchor = missingTrustAnchor;
    }

    public CertificateDetail getVerifiedTrustAnchor() {
        return verifiedTrustAnchor;
    }

    public void setVerifiedTrustAnchor(CertificateDetail verifiedTrustAnchor) {
        this.verifiedTrustAnchor = verifiedTrustAnchor;
    }

    public List<String> getDiagnosticLogs() {
        return diagnosticLogs;
    }

    public void setDiagnosticLogs(List<String> diagnosticLogs) {
        this.diagnosticLogs = diagnosticLogs;
    }

    public boolean isAnchorFromCandidateInput() {
        return anchorFromCandidateInput;
    }

    public void setAnchorFromCandidateInput(boolean anchorFromCandidateInput) {
        this.anchorFromCandidateInput = anchorFromCandidateInput;
    }
}
