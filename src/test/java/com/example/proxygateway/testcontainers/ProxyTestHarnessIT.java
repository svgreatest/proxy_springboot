package com.example.proxygateway.testcontainers;

import com.example.proxygateway.config.BcfipsSecurityConfig;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Educational Testcontainers Test Harness.
 *
 * <p>Validates containerized Squid proxy instances when Docker is available.
 * If Docker Desktop is not running, the test dynamically skips so the Maven build succeeds.</p>
 */
@Testcontainers
class ProxyTestHarnessIT {

    @BeforeAll
    static void checkDockerAvailability() {
        new BcfipsSecurityConfig().initFipsSecurityProviders();
        boolean dockerAvailable = false;
        try {
            dockerAvailable = DockerClientFactory.instance().isDockerAvailable();
        } catch (Exception ignored) {}
        Assumptions.assumeTrue(dockerAvailable, "Docker daemon is not available; skipping Testcontainers execution.");
    }

    @Container
    static GenericContainer<?> squidContainer = new GenericContainer<>("ubuntu/squid:latest")
            .withExposedPorts(3128)
            .waitingFor(Wait.forListeningPort());

    @Test
    void testSquidContainerLifecycle() {
        assertTrue(squidContainer.isRunning());
        Integer proxyPort = squidContainer.getMappedPort(3128);
        assertTrue(proxyPort > 0, "Squid forward proxy port successfully mapped: " + proxyPort);
    }
}
