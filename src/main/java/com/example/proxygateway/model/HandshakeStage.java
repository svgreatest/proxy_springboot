package com.example.proxygateway.model;

/**
 * Indicates which phase of TLS handshake occurred or encountered an issue.
 */
public enum HandshakeStage {
    /**
     * Handshake 1: Direct TLS connection to an HTTPS proxy itself.
     */
    PROXY_CONNECT_TLS,

    /**
     * Handshake 2: End-to-end TLS connection to the destination server
     * (or MITM inspection proxy certificate) inside the HTTP CONNECT tunnel.
     */
    TARGET_TLS,

    /**
     * Non-TLS stage (e.g. TCP connect or HTTP auth challenge).
     */
    NONE
}
