package com.example.proxygateway.util;

import com.example.proxygateway.config.BcfipsSecurityConfig;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Educational In-Process Mock Proxy Server.
 *
 * <p>Simulates:</p>
 * <ol>
 *   <li>Cleartext HTTP Forward Proxy with or without Basic Auth.</li>
 *   <li>MITM TLS Inspection Proxy: intercepts CONNECT tunnels and presents a dynamic
 *       certificate signed by a custom test Root CA.</li>
 * </ol>
 */
public class MockProxyServer implements AutoCloseable {

    private final int port;
    private final boolean requireAuth;
    private final String expectedUser;
    private final String expectedPass;
    private final TestCertHelper.KeyAndCert mitmRootCa;

    private ServerSocket serverSocket;
    private final ExecutorService executor = Executors.newCachedThreadPool();
    private final AtomicBoolean running = new AtomicBoolean(false);

    public MockProxyServer(int port, boolean requireAuth, String expectedUser, String expectedPass, TestCertHelper.KeyAndCert mitmRootCa) {
        this.port = port;
        this.requireAuth = requireAuth;
        this.expectedUser = expectedUser;
        this.expectedPass = expectedPass;
        this.mitmRootCa = mitmRootCa;
    }

    public static MockProxyServer createPlain(int port) {
        return new MockProxyServer(port, false, null, null, null);
    }

    public static MockProxyServer createWithAuth(int port, String user, String pass) {
        return new MockProxyServer(port, true, user, pass, null);
    }

    public static MockProxyServer createMitm(int port, TestCertHelper.KeyAndCert mitmRootCa) {
        return new MockProxyServer(port, false, null, null, mitmRootCa);
    }

    public void start() throws Exception {
        this.serverSocket = new ServerSocket(port);
        this.running.set(true);
        executor.submit(this::acceptLoop);
    }

    public int getPort() {
        return serverSocket.getLocalPort();
    }

    private void acceptLoop() {
        while (running.get() && !serverSocket.isClosed()) {
            try {
                Socket clientSocket = serverSocket.accept();
                executor.submit(() -> handleClient(clientSocket));
            } catch (Exception e) {
                if (!running.get()) break;
            }
        }
    }

    private void handleClient(Socket client) {
        try (client;
             BufferedReader reader = new BufferedReader(new InputStreamReader(client.getInputStream(), StandardCharsets.US_ASCII));
             OutputStream out = client.getOutputStream()) {

            String requestLine = reader.readLine();
            if (requestLine == null || requestLine.isEmpty()) return;

            String authHeader = null;
            String line;
            while ((line = reader.readLine()) != null && !line.isEmpty()) {
                if (line.toLowerCase().startsWith("proxy-authorization:")) {
                    authHeader = line.substring(line.indexOf(":") + 1).trim();
                }
            }

            // Check Authentication if required
            if (requireAuth) {
                boolean authenticated = false;
                if (authHeader != null && authHeader.startsWith("Basic ")) {
                    String creds = new String(java.util.Base64.getDecoder().decode(authHeader.substring(6).trim()));
                    if (creds.equals(expectedUser + ":" + expectedPass)) {
                        authenticated = true;
                    }
                }
                if (!authenticated) {
                    String resp = "HTTP/1.1 407 Proxy Authentication Required\r\n" +
                            "Proxy-Authenticate: Basic realm=\"Mock Proxy\"\r\n" +
                            "Content-Length: 0\r\n\r\n";
                    out.write(resp.getBytes(StandardCharsets.US_ASCII));
                    out.flush();
                    return;
                }
            }

            // Handle CONNECT or GET
            if (requestLine.startsWith("CONNECT ")) {
                handleConnect(requestLine, client, out);
            } else {
                // Mock HTTP 200 response
                String body = "{\"status\":\"ok\",\"proxy\":\"mock\"}";
                String resp = "HTTP/1.1 200 OK\r\n" +
                        "Content-Type: application/json\r\n" +
                        "Content-Length: " + body.length() + "\r\n\r\n" + body;
                out.write(resp.getBytes(StandardCharsets.US_ASCII));
                out.flush();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void handleConnect(String requestLine, Socket client, OutputStream out) throws Exception {
        // Parse host from "CONNECT host:port HTTP/1.1"
        String[] parts = requestLine.split(" ");
        String hostPort = parts[1];
        String targetHost = hostPort.split(":")[0];

        // Send 200 Connection Established
        String established = "HTTP/1.1 200 Connection Established\r\n\r\n";
        out.write(established.getBytes(StandardCharsets.US_ASCII));
        out.flush();

        // If MITM inspection is enabled, perform TLS handshake inside tunnel
        if (mitmRootCa != null) {
            TestCertHelper.KeyAndCert mitmLeaf = TestCertHelper.generateLeafCert(targetHost, mitmRootCa);

            KeyStore ks = KeyStore.getInstance("BCFKS", BcfipsSecurityConfig.BCFIPS_PROVIDER_NAME);
            ks.load(null, "pass".toCharArray());
            ks.setKeyEntry("mitm-server", mitmLeaf.keyPair().getPrivate(), "pass".toCharArray(),
                    new X509Certificate[]{mitmLeaf.certificate(), mitmRootCa.certificate()});

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX", BcfipsSecurityConfig.BCJSSE_PROVIDER_NAME);
            kmf.init(ks, "pass".toCharArray());

            SSLContext sslContext = SSLContext.getInstance("TLS", BcfipsSecurityConfig.BCJSSE_PROVIDER_NAME);
            sslContext.init(kmf.getKeyManagers(), null, null);

            javax.net.ssl.SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
            try (Socket sslSocket = sslSocketFactory.createSocket(client, null, client.getPort(), false)) {
                javax.net.ssl.SSLSocket serverTlsSocket = (javax.net.ssl.SSLSocket) sslSocket;
                serverTlsSocket.setUseClientMode(false);
                serverTlsSocket.startHandshake();

                // Send mock HTTPS response
                BufferedReader sslReader = new BufferedReader(new InputStreamReader(sslSocket.getInputStream()));
                String sslReq = sslReader.readLine();
                String body = "{\"message\":\"hello from mitm inspected destination\"}";
                String resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + body.length() + "\r\n\r\n" + body;
                sslSocket.getOutputStream().write(resp.getBytes(StandardCharsets.US_ASCII));
                sslSocket.getOutputStream().flush();
            }
        }
    }

    @Override
    public void close() {
        running.set(false);
        try {
            if (serverSocket != null) serverSocket.close();
        } catch (Exception ignored) {}
        executor.shutdownNow();
    }
}
