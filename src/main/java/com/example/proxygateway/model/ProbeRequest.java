package com.example.proxygateway.model;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * Request payload to probe connectivity through a proxy.
 */
public class ProbeRequest {

    @NotBlank(message = "Target URL must not be blank")
    private String targetUrl;

    @NotNull(message = "Proxy configuration is required")
    @Valid
    private ProxyConfig proxy;

    /**
     * Optional candidate Root CA PEM provided by the user in step 2.
     * When provided, this CA is loaded ONLY into the ephemeral in-memory trust store.
     */
    private String candidateRootPem;

    public ProbeRequest() {}

    public ProbeRequest(String targetUrl, ProxyConfig proxy) {
        this.targetUrl = targetUrl;
        this.proxy = proxy;
    }

    public ProbeRequest(String targetUrl, ProxyConfig proxy, String candidateRootPem) {
        this.targetUrl = targetUrl;
        this.proxy = proxy;
        this.candidateRootPem = candidateRootPem;
    }

    public String getTargetUrl() {
        return targetUrl;
    }

    public void setTargetUrl(String targetUrl) {
        this.targetUrl = targetUrl;
    }

    public ProxyConfig getProxy() {
        return proxy;
    }

    public void setProxy(ProxyConfig proxy) {
        this.proxy = proxy;
    }

    public String getCandidateRootPem() {
        return candidateRootPem;
    }

    public void setCandidateRootPem(String candidateRootPem) {
        this.candidateRootPem = candidateRootPem;
    }
}
