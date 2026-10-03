package com.example.proxygateway.model;

/**
 * Result status of a proxy probe request.
 */
public enum ProbeStatus {
    /**
     * Successfully established connection and received HTTP 2xx/3xx response.
     */
    SUCCESS,

    /**
     * Handshake failed because the target or MITM inspection Root CA is untrusted / missing from the trust store.
     */
    FAILED_UNTRUSTED_ROOT,

    /**
     * Handshake failed because the HTTPS proxy server's own certificate is untrusted.
     */
    FAILED_UNTRUSTED_PROXY,

    /**
     * Proxy returned 407 Proxy Authentication Required or bad credentials.
     */
    FAILED_PROXY_AUTH,

    /**
     * Connection timeout, refusal, or DNS failure.
     */
    FAILED_CONNECTION
}
