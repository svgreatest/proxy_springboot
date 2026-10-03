package com.example.proxygateway.util;

import com.example.proxygateway.config.BcfipsSecurityConfig;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

/**
 * Educational Test Utility for dynamically generating X.509 CAs and leaf certificates
 * using BCFIPS in unit and integration tests.
 */
public class TestCertHelper {

    public record KeyAndCert(KeyPair keyPair, X509Certificate certificate) {}

    public static KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BcfipsSecurityConfig.BCFIPS_PROVIDER_NAME);
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    /**
     * Generates a self-signed Root CA certificate with proper CA BasicConstraints and KeyUsage.
     */
    public static KeyAndCert generateRootCa(String commonName) throws Exception {
        KeyPair keyPair = generateRsaKeyPair();
        X500Name issuer = new X500Name("CN=" + commonName + ", O=Test Corp, C=US");
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = Date.from(Instant.now().minus(1, ChronoUnit.DAYS));
        Date notAfter = Date.from(Instant.now().plus(365, ChronoUnit.DAYS));

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, issuer, keyPair.getPublic()
        );

        // Mark as CA (BasicConstraints isCA=true)
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        // KeyUsage: keyCertSign and cRLSign are required for Root CAs in PKIX
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BcfipsSecurityConfig.BCFIPS_PROVIDER_NAME)
                .build(keyPair.getPrivate());

        X509CertificateHolder holder = builder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider(BcfipsSecurityConfig.BCFIPS_PROVIDER_NAME)
                .getCertificate(holder);

        return new KeyAndCert(keyPair, cert);
    }

    /**
     * Generates a Leaf certificate signed by the specified Root CA.
     */
    public static KeyAndCert generateLeafCert(String commonName, KeyAndCert rootCa) throws Exception {
        KeyPair keyPair = generateRsaKeyPair();
        X500Name subject = new X500Name("CN=" + commonName + ", O=Test Corp, C=US");
        X500Name issuer = X500Name.getInstance(rootCa.certificate().getSubjectX500Principal().getEncoded());
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis() + 100);
        Date notBefore = Date.from(Instant.now().minus(1, ChronoUnit.DAYS));
        Date notAfter = Date.from(Instant.now().plus(30, ChronoUnit.DAYS));

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, keyPair.getPublic()
        );

        builder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

        // Add Subject Alternative Name (SAN) for hostname and IP address verification
        org.bouncycastle.asn1.x509.GeneralName[] names;
        if (commonName.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
            names = new org.bouncycastle.asn1.x509.GeneralName[]{
                    new org.bouncycastle.asn1.x509.GeneralName(org.bouncycastle.asn1.x509.GeneralName.iPAddress, commonName),
                    new org.bouncycastle.asn1.x509.GeneralName(org.bouncycastle.asn1.x509.GeneralName.dNSName, "localhost")
            };
        } else {
            names = new org.bouncycastle.asn1.x509.GeneralName[]{
                    new org.bouncycastle.asn1.x509.GeneralName(org.bouncycastle.asn1.x509.GeneralName.dNSName, commonName),
                    new org.bouncycastle.asn1.x509.GeneralName(org.bouncycastle.asn1.x509.GeneralName.iPAddress, "127.0.0.1")
            };
        }
        builder.addExtension(Extension.subjectAlternativeName, false, new org.bouncycastle.asn1.x509.GeneralNames(names));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BcfipsSecurityConfig.BCFIPS_PROVIDER_NAME)
                .build(rootCa.keyPair().getPrivate());

        X509CertificateHolder holder = builder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider(BcfipsSecurityConfig.BCFIPS_PROVIDER_NAME)
                .getCertificate(holder);

        return new KeyAndCert(keyPair, cert);
    }
}
