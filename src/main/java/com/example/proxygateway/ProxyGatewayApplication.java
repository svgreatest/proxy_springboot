package com.example.proxygateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Spring Boot Application Entry Point for Proxy Gateway with Capturing & In-Memory Trust Manager.
 */
@SpringBootApplication
public class ProxyGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(ProxyGatewayApplication.class, args);
    }
}
