package com.example.proxygateway.ssl;

import com.example.proxygateway.model.CertificateDetail;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

/**
 * Educational Utility for inspecting, converting, and formatting X.509 Certificates.
 */
public class CertificateInspector {

    private static final String CERT_FACTORY_TYPE = "X.509";

    /**
     * Converts a raw Java X509Certificate into our rich educational DTO.
     */
    public static CertificateDetail toDetail(X509Certificate cert) {
        return toDetail(null, cert);
    }

    /**
     * Converts a raw Java X509Certificate with known alias into our rich educational DTO.
     */
    public static CertificateDetail toDetail(String alias, X509Certificate cert) {
        if (cert == null) {
            return null;
        }
        boolean isSelfSigned = isSelfSigned(cert);
        String sha256 = getSha256Fingerprint(cert);
        String sha1 = getSha1Fingerprint(cert);
        String pem = toPem(cert);

        PublicKey pubKey = cert.getPublicKey();
        String keyAlgorithm = pubKey != null ? pubKey.getAlgorithm() : "UNKNOWN";
        int keySize = getKeySize(pubKey);
        String basicConstraints = extractBasicConstraints(cert);
        List<String> keyUsage = extractKeyUsage(cert);
        String explanation = generateEducationalExplanation(cert, isSelfSigned, keySize, keyAlgorithm, basicConstraints, keyUsage);

        CertificateDetail detail = new CertificateDetail(
                cert.getSubjectX500Principal().getName(),
                cert.getIssuerX500Principal().getName(),
                cert.getSerialNumber().toString(16),
                cert.getNotBefore().toInstant(),
                cert.getNotAfter().toInstant(),
                cert.getSigAlgName(),
                sha256,
                isSelfSigned,
                pem
        );
        detail.setAlias(alias);
        detail.setSha1Fingerprint(sha1);
        detail.setVersion(cert.getVersion());
        detail.setKeyAlgorithm(keyAlgorithm);
        detail.setKeySize(keySize);
        detail.setBasicConstraints(basicConstraints);
        detail.setKeyUsage(keyUsage);
        detail.setEducationalExplanation(explanation);

        return detail;
    }

    /**
     * Extracts cryptographic key bit length (e.g. 2048, 4096 for RSA; 256, 384 for EC).
     */
    public static int getKeySize(PublicKey pubKey) {
        if (pubKey instanceof java.security.interfaces.RSAPublicKey rsa) {
            return rsa.getModulus().bitLength();
        } else if (pubKey instanceof java.security.interfaces.ECPublicKey ec) {
            return ec.getParams().getOrder().bitLength();
        } else if (pubKey instanceof java.security.interfaces.DSAPublicKey dsa) {
            return dsa.getParams().getP().bitLength();
        }
        return 0;
    }

    /**
     * Calculates the SHA-1 fingerprint formatted with colon separators (e.g., AA:BB:CC:...).
     */
    public static String getSha1Fingerprint(X509Certificate cert) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] digest = md.digest(cert.getEncoded());
            String hex = HexFormat.of().withUpperCase().formatHex(digest);
            StringBuilder formatted = new StringBuilder();
            for (int i = 0; i < hex.length(); i += 2) {
                if (i > 0) formatted.append(":");
                formatted.append(hex, i, i + 2);
            }
            return formatted.toString();
        } catch (Exception e) {
            return "UNKNOWN";
        }
    }

    /**
     * Extracts Basic Constraints extension (CA flag and path length constraint).
     */
    public static String extractBasicConstraints(X509Certificate cert) {
        int bc = cert.getBasicConstraints();
        if (bc >= 0) {
            return "CA=true, pathlen=" + (bc == Integer.MAX_VALUE ? "unlimited" : bc);
        } else {
            return "CA=false (End-Entity / Leaf Certificate)";
        }
    }

    /**
     * Extracts standard RFC 5280 Key Usage flags.
     */
    public static List<String> extractKeyUsage(X509Certificate cert) {
        List<String> usages = new ArrayList<>();
        boolean[] ku = cert.getKeyUsage();
        if (ku == null) {
            usages.add("Not Specified (General / Unrestricted)");
            return usages;
        }
        String[] names = {
                "Digital Signature",                  // 0
                "Non-Repudiation (Content Commitment)",// 1
                "Key Encipherment",                  // 2
                "Data Encipherment",                 // 3
                "Key Agreement",                     // 4
                "Certificate Signing (keyCertSign)", // 5
                "CRL Signing (cRLSign)",             // 6
                "Encipher Only",                     // 7
                "Decipher Only"                      // 8
        };
        for (int i = 0; i < ku.length && i < names.length; i++) {
            if (ku[i]) {
                usages.add(names[i]);
            }
        }
        return usages;
    }

    /**
     * Synthesizes an educational, plain-English breakdown of the certificate's cryptographic role.
     */
    public static String generateEducationalExplanation(X509Certificate cert, boolean isSelfSigned,
                                                        int keySize, String keyAlgorithm,
                                                        String basicConstraints, List<String> keyUsage) {
        StringBuilder sb = new StringBuilder();
        Instant now = Instant.now();
        Instant notBefore = cert.getNotBefore().toInstant();
        Instant notAfter = cert.getNotAfter().toInstant();

        // 1. Role in PKI
        if (isSelfSigned) {
            sb.append("🏛️ **Root Certificate Authority (Trust Anchor)**: This certificate is self-signed (Subject matches Issuer). It serves as an ultimate trust anchor. TLS clients must have this certificate explicitly imported into their trust store to validate chains issued by this authority.\n\n");
        } else if (basicConstraints.contains("CA=true")) {
            sb.append("🏢 **Intermediate Certificate Authority**: This certificate was signed by an upstream CA. It possesses CA privileges to issue certificates to end-entity servers or subordinate CAs.\n\n");
        } else {
            sb.append("💻 **End-Entity (Leaf) Certificate**: This certificate identifies an individual server, proxy, or domain. It cannot issue or sign certificates.\n\n");
        }

        // 2. Cryptographic Security
        sb.append("🛡️ **Cryptographic Profile**: Uses **").append(keyAlgorithm).append("** with a key size of **")
          .append(keySize > 0 ? keySize + " bits" : "unknown").append("** and signed using **")
          .append(cert.getSigAlgName()).append("**.\n\n");

        // 3. Key Permissions
        sb.append("🔑 **Usage & Constraints**: Basic Constraints is `").append(basicConstraints).append("`.");
        if (!keyUsage.isEmpty()) {
            sb.append(" Granted key capabilities: `").append(String.join("`, `", keyUsage)).append("`.");
        }
        sb.append("\n\n");

        // 4. Validity Window
        if (now.isBefore(notBefore)) {
            sb.append("⚠️ **Validity Alert**: This certificate is **not yet valid** (starts on ").append(notBefore).append(").");
        } else if (now.isAfter(notAfter)) {
            sb.append("❌ **Validity Alert**: This certificate **expired** on ").append(notAfter).append(". Connections using this cert will fail TLS validation.");
        } else {
            sb.append("✅ **Validity**: Currently active and trusted until **").append(notAfter).append("**.");
        }

        return sb.toString();
    }

    /**
     * Determines whether a certificate is self-signed:
     * 1. Subject DN equals Issuer DN.
     * 2. Certificate's signature verifies using its own public key.
     */
    public static boolean isSelfSigned(X509Certificate cert) {
        if (cert == null) return false;
        if (!cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
            return false;
        }
        try {
            cert.verify(cert.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Strictly verifies that a certificate is a Root CA or self-signed certificate.
     * Rejects intermediate CAs and end-entity (leaf) certificates.
     *
     * @param cert X509Certificate to inspect
     * @throws IllegalArgumentException if the certificate is not self-signed / root CA
     */
    public static void validateRootCaOrSelfSigned(X509Certificate cert) {
        if (cert == null) {
            throw new IllegalArgumentException("Certificate cannot be null");
        }
        if (!isSelfSigned(cert)) {
            throw new IllegalArgumentException(
                    "Rejected: Only Root CA or self-signed certificates can be added as trust anchors. " +
                    "Presented certificate is an intermediate or leaf certificate: Subject=['" +
                    cert.getSubjectX500Principal().getName() + "'], Issuer=['" +
                    cert.getIssuerX500Principal().getName() + "']."
            );
        }
    }

    /**
     * Calculates the SHA-256 fingerprint formatted with colon separators (e.g., AA:BB:CC:...).
     */
    public static String getSha256Fingerprint(X509Certificate cert) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(cert.getEncoded());
            String hex = HexFormat.of().withUpperCase().formatHex(digest);
            // Insert colon every 2 characters
            StringBuilder formatted = new StringBuilder();
            for (int i = 0; i < hex.length(); i += 2) {
                if (i > 0) formatted.append(":");
                formatted.append(hex, i, i + 2);
            }
            return formatted.toString();
        } catch (Exception e) {
            return "UNKNOWN";
        }
    }

    /**
     * Converts an X509Certificate to standard PEM text representation (RFC 7468).
     */
    public static String toPem(X509Certificate cert) {
        try {
            StringWriter sw = new StringWriter();
            try (JcaPEMWriter writer = new JcaPEMWriter(sw)) {
                writer.writeObject(cert);
            }
            return sw.toString().trim();
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * Parses one or more X509Certificates from a PEM string.
     */
    public static List<X509Certificate> parsePemCertificates(String pemString) {
        List<X509Certificate> certs = new ArrayList<>();
        if (pemString == null || pemString.trim().isEmpty()) {
            return certs;
        }
        try {
            CertificateFactory factory = CertificateFactory.getInstance(CERT_FACTORY_TYPE);
            ByteArrayInputStream bais = new ByteArrayInputStream(pemString.getBytes(StandardCharsets.UTF_8));
            var collection = factory.generateCertificates(bais);
            for (var cert : collection) {
                if (cert instanceof X509Certificate x509) {
                    certs.add(x509);
                }
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse X.509 certificate from PEM: " + e.getMessage(), e);
        }
        return certs;
    }

    /**
     * Parses a single X509Certificate from a PEM string.
     */
    public static X509Certificate parseSinglePem(String pemString) {
        List<X509Certificate> certs = parsePemCertificates(pemString);
        if (certs.isEmpty()) {
            throw new IllegalArgumentException("No valid X.509 certificate found in PEM data");
        }
        return certs.get(0);
    }
}
