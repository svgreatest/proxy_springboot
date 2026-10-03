package com.example.proxygateway.model;

public class CommitResponse {

    private boolean success;
    private String alias;
    private String subjectDn;
    private String sha256Fingerprint;
    private String message;

    public CommitResponse() {}

    public CommitResponse(boolean success, String alias, String subjectDn, String sha256Fingerprint, String message) {
        this.success = success;
        this.alias = alias;
        this.subjectDn = subjectDn;
        this.sha256Fingerprint = sha256Fingerprint;
        this.message = message;
    }

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public String getSubjectDn() {
        return subjectDn;
    }

    public void setSubjectDn(String subjectDn) {
        this.subjectDn = subjectDn;
    }

    public String getSha256Fingerprint() {
        return sha256Fingerprint;
    }

    public void setSha256Fingerprint(String sha256Fingerprint) {
        this.sha256Fingerprint = sha256Fingerprint;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
