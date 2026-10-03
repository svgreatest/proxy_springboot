package com.example.proxygateway.model;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Educational DTO detailing a certificate with rich cryptographic breakdown and plain-English explanations.
 */
public class CertificateDetail {

    private String alias;
    private String subjectDn;
    private String issuerDn;
    private String serialNumber;
    private Instant notBefore;
    private Instant notAfter;
    private String sigAlgName;
    private String sha256Fingerprint;
    private String sha1Fingerprint;
    private boolean selfSigned;
    private String pem;

    // Rich Educational & Cryptographic Breakdown
    private int version;
    private String keyAlgorithm;
    private int keySize;
    private String basicConstraints;
    private List<String> keyUsage = new ArrayList<>();
    private String educationalExplanation;

    public CertificateDetail() {}

    public CertificateDetail(String subjectDn, String issuerDn, String serialNumber,
                             Instant notBefore, Instant notAfter, String sigAlgName,
                             String sha256Fingerprint, boolean selfSigned, String pem) {
        this.subjectDn = subjectDn;
        this.issuerDn = issuerDn;
        this.serialNumber = serialNumber;
        this.notBefore = notBefore;
        this.notAfter = notAfter;
        this.sigAlgName = sigAlgName;
        this.sha256Fingerprint = sha256Fingerprint;
        this.selfSigned = selfSigned;
        this.pem = pem;
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

    public Instant getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(Instant notBefore) {
        this.notBefore = notBefore;
    }

    public Instant getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(Instant notAfter) {
        this.notAfter = notAfter;
    }

    public String getSigAlgName() {
        return sigAlgName;
    }

    public void setSigAlgName(String sigAlgName) {
        this.sigAlgName = sigAlgName;
    }

    public String getSha256Fingerprint() {
        return sha256Fingerprint;
    }

    public void setSha256Fingerprint(String sha256Fingerprint) {
        this.sha256Fingerprint = sha256Fingerprint;
    }

    public String getSha1Fingerprint() {
        return sha1Fingerprint;
    }

    public void setSha1Fingerprint(String sha1Fingerprint) {
        this.sha1Fingerprint = sha1Fingerprint;
    }

    public boolean isSelfSigned() {
        return selfSigned;
    }

    public void setSelfSigned(boolean selfSigned) {
        this.selfSigned = selfSigned;
    }

    public String getPem() {
        return pem;
    }

    public void setPem(String pem) {
        this.pem = pem;
    }

    public int getVersion() {
        return version;
    }

    public void setVersion(int version) {
        this.version = version;
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

    public String getBasicConstraints() {
        return basicConstraints;
    }

    public void setBasicConstraints(String basicConstraints) {
        this.basicConstraints = basicConstraints;
    }

    public List<String> getKeyUsage() {
        return keyUsage;
    }

    public void setKeyUsage(List<String> keyUsage) {
        this.keyUsage = keyUsage != null ? keyUsage : new ArrayList<>();
    }

    public String getEducationalExplanation() {
        return educationalExplanation;
    }

    public void setEducationalExplanation(String educationalExplanation) {
        this.educationalExplanation = educationalExplanation;
    }
}
