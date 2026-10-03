package com.example.proxygateway.model;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * Representation of forward proxy settings.
 */
public class ProxyConfig {

    @NotBlank(message = "Proxy host cannot be blank")
    private String host;

    @Min(value = 1, message = "Proxy port must be between 1 and 65535")
    @Max(value = 65535, message = "Proxy port must be between 1 and 65535")
    private int port = 3128;

    @NotNull(message = "Proxy protocol must be specified")
    private ProxyProtocol protocol = ProxyProtocol.HTTP;

    private String username;
    private String password;

    public ProxyConfig() {}

    public ProxyConfig(String host, int port, ProxyProtocol protocol) {
        this.host = host;
        this.port = port;
        this.protocol = protocol;
    }

    public ProxyConfig(String host, int port, ProxyProtocol protocol, String username, String password) {
        this.host = host;
        this.port = port;
        this.protocol = protocol;
        this.username = username;
        this.password = password;
    }

    public boolean hasAuth() {
        return username != null && !username.trim().isEmpty();
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public ProxyProtocol getProtocol() {
        return protocol;
    }

    public void setProtocol(ProxyProtocol protocol) {
        this.protocol = protocol;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    public String toString() {
        return protocol.name().toLowerCase() + "://" + (hasAuth() ? (username + ":***@") : "") + host + ":" + port;
    }
}
