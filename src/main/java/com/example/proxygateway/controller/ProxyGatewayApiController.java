package com.example.proxygateway.controller;

import com.example.proxygateway.model.CertificateDetail;
import com.example.proxygateway.model.CommitRequest;
import com.example.proxygateway.model.CommitResponse;
import com.example.proxygateway.model.ProbeRequest;
import com.example.proxygateway.model.ProbeResponse;
import com.example.proxygateway.model.TrustStoreEntry;
import com.example.proxygateway.service.ProxyProbeService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Educational REST Controller exposing:
 * <ul>
 *   <li>Single Probe API: establishes connection through proxy and diagnoses TLS chains.</li>
 *   <li>Commit API: commits verified Root CA only upon successful connection.</li>
 *   <li>TrustStore Management APIs: list and delete persisted trust anchors.</li>
 * </ul>
 */
@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class ProxyGatewayApiController {

    private final ProxyProbeService proxyProbeService;

    public ProxyGatewayApiController(ProxyProbeService proxyProbeService) {
        this.proxyProbeService = proxyProbeService;
    }

    /**
     * Single API to probe connection to a remote website through a proxy.
     * Uses Ephemeral In-Memory TrustStore. Leaves persistent store untouched.
     */
    @PostMapping("/proxy/probe")
    public ResponseEntity<ProbeResponse> probeProxyConnection(@Valid @RequestBody ProbeRequest request) {
        ProbeResponse response = proxyProbeService.probe(request);
        return ResponseEntity.ok(response);
    }

    /**
     * Commits a verified Root CA to the persistent BCFKS trust store.
     */
    @PostMapping("/proxy/commit")
    public ResponseEntity<CommitResponse> commitRootCa(@Valid @RequestBody CommitRequest request) {
        CommitResponse response = proxyProbeService.commitRootCa(request);
        return ResponseEntity.ok(response);
    }

    /**
     * Lists active trust anchors in the persistent BCFKS store.
     */
    @GetMapping("/truststore")
    public ResponseEntity<List<TrustStoreEntry>> listTrustStoreEntries() {
        return ResponseEntity.ok(proxyProbeService.listTrustStoreEntries());
    }

    /**
     * Retrieves full cryptographic details and educational explanation for a specific trust anchor.
     */
    @GetMapping("/truststore/{alias}")
    public ResponseEntity<CertificateDetail> getTrustStoreEntryDetail(@PathVariable String alias) {
        CertificateDetail detail = proxyProbeService.getTrustStoreEntryDetail(alias);
        return detail != null ? ResponseEntity.ok(detail) : ResponseEntity.notFound().build();
    }

    /**
     * Deletes a trust anchor from the persistent store.
     */
    @DeleteMapping("/truststore/{alias}")
    public ResponseEntity<Void> deleteTrustStoreEntry(@PathVariable String alias) {
        boolean deleted = proxyProbeService.deleteTrustStoreEntry(alias);
        return deleted ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    /**
     * Helper endpoint to fetch the test-harness mitmproxy Root CA certificate if present.
     */
    @GetMapping("/test-harness/mitm-cert")
    public ResponseEntity<java.util.Map<String, String>> getTestHarnessMitmCert() {
        java.io.File certFile = new java.io.File("test-harness/mitmproxy/certs/mitmproxy-ca-cert.pem");
        if (!certFile.exists()) {
            certFile = new java.io.File("../test-harness/mitmproxy/certs/mitmproxy-ca-cert.pem");
        }
        if (certFile.exists()) {
            try {
                String pem = java.nio.file.Files.readString(certFile.toPath());
                return ResponseEntity.ok(java.util.Map.of("pem", pem, "status", "FOUND"));
            } catch (Exception e) {
                return ResponseEntity.ok(java.util.Map.of("status", "ERROR", "message", e.getMessage()));
            }
        }
        return ResponseEntity.ok(java.util.Map.of("status", "NOT_FOUND"));
    }

    /**
     * Helper endpoint to fetch the test-harness HTTPS proxy certificate (squid port 8443).
     */
    @GetMapping("/test-harness/https-proxy-cert")
    public ResponseEntity<java.util.Map<String, String>> getTestHarnessHttpsProxyCert() {
        java.io.File certFile = new java.io.File("test-harness/squid/ssl/proxy-server.crt");
        if (!certFile.exists()) {
            certFile = new java.io.File("../test-harness/squid/ssl/proxy-server.crt");
        }
        if (certFile.exists()) {
            try {
                String pem = java.nio.file.Files.readString(certFile.toPath());
                return ResponseEntity.ok(java.util.Map.of("pem", pem, "status", "FOUND"));
            } catch (Exception e) {
                return ResponseEntity.ok(java.util.Map.of("status", "ERROR", "message", e.getMessage()));
            }
        }
        return ResponseEntity.ok(java.util.Map.of("status", "NOT_FOUND"));
    }
}
