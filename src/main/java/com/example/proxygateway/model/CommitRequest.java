package com.example.proxygateway.model;

import jakarta.validation.constraints.NotBlank;

public class CommitRequest {

    @NotBlank(message = "Root CA PEM is required")
    private String rootPem;

    private String alias;

    public CommitRequest() {}

    public CommitRequest(String rootPem, String alias) {
        this.rootPem = rootPem;
        this.alias = alias;
    }

    public String getRootPem() {
        return rootPem;
    }

    public void setRootPem(String rootPem) {
        this.rootPem = rootPem;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }
}
