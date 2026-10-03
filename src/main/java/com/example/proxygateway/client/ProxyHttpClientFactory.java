package com.example.proxygateway.client;

import com.example.proxygateway.model.HandshakeStage;
import com.example.proxygateway.model.ProxyConfig;
import com.example.proxygateway.model.ProxyProtocol;
import com.example.proxygateway.ssl.HandshakeCaptureContext;
import com.example.proxygateway.ssl.LogCollector;
import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.impl.routing.DefaultProxyRoutePlanner;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.util.Timeout;
import org.springframework.stereotype.Component;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

/**
 * Educational Apache HttpClient 5 Factory.
 *
 * <p>Supports all 8 Proxy Combinations + Direct, including:
 * <ul>
 *   <li>Direct TLS to HTTPS Proxy (RFC 2817 / TLS-to-proxy tunneling).</li>
 *   <li>Multi-stage TLS tracking: PROXY_CONNECT_TLS vs TARGET_TLS.</li>
 *   <li>Basic Proxy Authentication over cleartext or TLS.</li>
 *   <li>Full certificate capture at every handshake layer.</li>
 * </ul>
 */
@Component
public class ProxyHttpClientFactory {

    public CloseableHttpClient createClient(ProxyConfig proxyConfig, SSLContext sslContext) {
        LogCollector.log("🌐", "[HTTP CLIENT 5] Building client with proxy: {}", proxyConfig);

        // 1. Route Planner (HTTP / HTTPS Proxy or Direct)
        DefaultProxyRoutePlanner routePlanner = null;
        if (proxyConfig != null && proxyConfig.getHost() != null && !proxyConfig.getHost().trim().isEmpty() && proxyConfig.getPort() > 0) {
            String scheme = proxyConfig.getProtocol() != null ? proxyConfig.getProtocol().name().toLowerCase() : "http";
            HttpHost proxy = new HttpHost(scheme, proxyConfig.getHost(), proxyConfig.getPort());
            routePlanner = new DefaultProxyRoutePlanner(proxy);
            LogCollector.log("🧭", "Configured proxy route via: {}://{}:{}", scheme, proxyConfig.getHost(), proxyConfig.getPort());
        } else {
            LogCollector.log("🧭", "Configured direct connection (no proxy)");
        }

        // 2. Multi-Stage TLS Socket Factory tracking Handshake Stages
        SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(
                sslContext,
                NoopHostnameVerifier.INSTANCE
        ) {
            @Override
            public Socket connectSocket(Socket socket, HttpHost host, InetSocketAddress remoteAddress,
                                        InetSocketAddress localAddress, Timeout connectTimeout,
                                        Object attachment, HttpContext context) throws IOException {
                if (proxyConfig != null && proxyConfig.getProtocol() == ProxyProtocol.HTTPS &&
                        host.getHostName().equalsIgnoreCase(proxyConfig.getHost()) &&
                        host.getPort() == proxyConfig.getPort()) {
                    LogCollector.log("🔒", "Initiating Direct Proxy TLS connection to {}:{}", host.getHostName(), host.getPort());
                    HandshakeCaptureContext.get().setCurrentStage(HandshakeStage.PROXY_CONNECT_TLS);
                } else {
                    LogCollector.log("🔒", "Initiating Target TLS connection to {}:{}", host.getHostName(), host.getPort());
                    HandshakeCaptureContext.get().setCurrentStage(HandshakeStage.TARGET_TLS);
                }
                return super.connectSocket(socket, host, remoteAddress, localAddress, connectTimeout, attachment, context);
            }

            @Override
            public Socket createLayeredSocket(Socket socket, String target, int port, Object attachment, HttpContext context) throws IOException {
                if (proxyConfig != null && proxyConfig.getProtocol() == ProxyProtocol.HTTPS &&
                        target.equalsIgnoreCase(proxyConfig.getHost()) &&
                        port == proxyConfig.getPort()) {
                    LogCollector.log("🔒", "Initiating Direct Proxy TLS handshake to {}:{}", target, port);
                    HandshakeCaptureContext.get().setCurrentStage(HandshakeStage.PROXY_CONNECT_TLS);
                } else {
                    LogCollector.log("🔒", "Initiating Layered Target TLS handshake over proxy tunnel to {}:{}", target, port);
                    HandshakeCaptureContext.get().setCurrentStage(HandshakeStage.TARGET_TLS);
                }
                return super.createLayeredSocket(socket, target, port, attachment, context);
            }

            @Override
            public Socket createLayeredSocket(Socket socket, String target, int port, HttpContext context) throws IOException {
                return createLayeredSocket(socket, target, port, null, context);
            }
        };

        // 3. Connection Manager
        PoolingHttpClientConnectionManager connectionManager = PoolingHttpClientConnectionManagerBuilder.create()
                .setSSLSocketFactory(sslSocketFactory)
                .setMaxConnTotal(10)
                .setMaxConnPerRoute(5)
                .build();

        // 4. Request Timeout Settings (5 seconds for responsive probe)
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(Timeout.ofSeconds(6))
                .setResponseTimeout(Timeout.ofSeconds(8))
                .setConnectionRequestTimeout(Timeout.ofSeconds(6))
                .build();

        var clientBuilder = HttpClients.custom()
                .setConnectionManager(connectionManager)
                .setRoutePlanner(routePlanner)
                .setDefaultRequestConfig(requestConfig);

        // 5. Proxy Authentication if configured
        if (proxyConfig != null && proxyConfig.hasAuth()) {
            BasicCredentialsProvider credentialsProvider = new BasicCredentialsProvider();
            AuthScope authScope = new AuthScope(proxyConfig.getHost(), proxyConfig.getPort());
            credentialsProvider.setCredentials(
                    authScope,
                    new UsernamePasswordCredentials(proxyConfig.getUsername(), proxyConfig.getPassword().toCharArray())
            );
            clientBuilder.setDefaultCredentialsProvider(credentialsProvider);
            LogCollector.log("🔑", "Configured Proxy-Authorization credentials for user '{}' on {}:{}",
                    proxyConfig.getUsername(), proxyConfig.getHost(), proxyConfig.getPort());
        }

        return clientBuilder.build();
    }
}
