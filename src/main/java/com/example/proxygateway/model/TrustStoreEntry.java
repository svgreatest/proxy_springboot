package com.example.proxygateway.model;

import java.time.Instant;

/**
 * Representation of an active committed trust anchor in the BCFKS keystore.
 */
public class TrustStoreEntry {

    private String alias;
    private String subjectDn;
    private String issuerDn;
    private String serialNumber;
    private String sha256Fingerprint;
    private Instant notAfter;
    private Instant notBefore;
    private boolean selfSigned;
    private boolean systemRoot;
    private String keyAlgorithm;
    private int keySize;

    public TrustStoreEntry() {}

    public TrustStoreEntry(String alias, String subjectDn, String issuerDn, String serialNumber,
                           String sha256Fingerprint, Instant notAfter, boolean selfSigned) {
        this(alias, subjectDn, issuerDn, serialNumber, sha256Fingerprint, notAfter, null, selfSigned,
                alias != null && alias.startsWith("system-"), "RSA", 2048);
    }

    public TrustStoreEntry(String alias, String subjectDn, String issuerDn, String serialNumber,
                           String sha256Fingerprint, Instant notAfter, Instant notBefore,
                           boolean selfSigned, boolean systemRoot, String keyAlgorithm, int keySize) {
        this.alias = alias;
        this.subjectDn = subjectDn;
        this.issuerDn = issuerDn;
        this.serialNumber = serialNumber;
        this.sha256Fingerprint = sha256Fingerprint;
        this.notAfter = notAfter;
        this.notBefore = notBefore;
        this.selfSigned = selfSigned;
        this.systemRoot = systemRoot;
        this.keyAlgorithm = keyAlgorithm;
        this.keySize = keySize;
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

    public String getIssuerDn() {
        return issuerDn;
    }

    public void setIssuerDn(String issuerDn) {
        this.issuerDn = issuerDn;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getSha256Fingerprint() {
        return sha256Fingerprint;
    }

    public void setSha256Fingerprint(String sha256Fingerprint) {
        this.sha256Fingerprint = sha256Fingerprint;
    }

    public Instant getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(Instant notAfter) {
        this.notAfter = notAfter;
    }

    public Instant getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(Instant notBefore) {
        this.notBefore = notBefore;
    }

    public boolean isSelfSigned() {
        return selfSigned;
    }

    public void setSelfSigned(boolean selfSigned) {
        this.selfSigned = selfSigned;
    }

    public boolean isSystemRoot() {
        return systemRoot;
    }

    public void setSystemRoot(boolean systemRoot) {
        this.systemRoot = systemRoot;
    }

    public String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public void setKeyAlgorithm(String keyAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
    }

    public int getKeySize() {
        return keySize;
    }

    public void setKeySize(int keySize) {
        this.keySize = keySize;
    }
}
