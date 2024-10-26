package com.github.alexsc.cms;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class Main {
    private static final String PFX_FILE = "src/main/resources/keystore-local.p12";
    private static final String PFX_PASSWORD = "ks-password";

    private static PrivateKey loadPrivateKeyFromPfx(String pfxFile, String pfxPassword) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(pfxFile)) {
            keyStore.load(fis, PFX_PASSWORD.toCharArray());
        }

        String alias = keyStore.aliases().nextElement();
        return (PrivateKey) keyStore.getKey(alias, pfxPassword.toCharArray());
    }

    private static Certificate[] loadCertificateFromPfx(String pfxFile, String pfxPassword) throws Exception {
        // Load the PFX file into a KeyStore
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(pfxFile)) {
            keyStore.load(fis, pfxPassword.toCharArray());
        }

        String alias = keyStore.aliases().nextElement();
        return keyStore.getCertificateChain(alias);
    }

    private static CMSSignedData createCMSSignature(byte[] dataToSign, String pfxFile, String pfxPassword) throws Exception {
        var privateKey = loadPrivateKeyFromPfx(pfxFile, pfxPassword);
        var certificateChain = loadCertificateFromPfx(pfxFile, pfxPassword);
        var certificate = (X509Certificate) certificateChain[0];

        // Prepare a digest calculator for hashing the data
        var digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().build();

        // Create content signer for signing data
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(privateKey);

        // Convert certificate to BouncyCastle format
        X509CertificateHolder certHolder = new JcaX509CertificateHolder(certificate);

        // Create a CMS Signed Data Generator
        CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
        cmsGenerator.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(digestCalculatorProvider)
                        .build(contentSigner, certHolder)
        );

        // Add the certificate to the generator
        List<X509CertificateHolder> certList = new ArrayList<>();
        certList.add(certHolder);
        Store<?> certs = new JcaCertStore(certList);
        cmsGenerator.addCertificates(certs);

        // Prepare data to sign
        CMSTypedData cmsData = new CMSProcessableByteArray(dataToSign);

        // Generate CMS Signed Data
        return cmsGenerator.generate(cmsData, true);
    }

    public static void main(String[] args) throws Exception {
        byte[] data = Files.readAllBytes(Path.of("pom.xml"));

        // Generate CMS signature
        CMSSignedData signedData = createCMSSignature(data, PFX_FILE, PFX_PASSWORD);

        // Output signed data in encoded form
        byte[] signedBytes = signedData.getEncoded();
        Files.write(Path.of("pom.xml.p7b"), signedBytes);
    }
}
