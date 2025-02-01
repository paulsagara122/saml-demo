package saml.sp;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.*;

import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

@Configuration
public class SamlConfig {

    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
        RelyingPartyRegistration registration = RelyingPartyRegistrations
                .fromMetadataLocation("classpath:idp-metadata.xml")
                .entityId("http://localhost:8080/saml/sp")
                .registrationId("my-saml-sp")
                .assertingPartyDetails(details ->
                        details.entityId("http://localhost:9090/api/v1/saml/auth/login")
                                .singleSignOnServiceLocation("http://localhost:9090/api/v1/saml/auth/login")
                                .wantAuthnRequestsSigned(true)
                                .verificationX509Credentials(c -> c.add(createVerificationCredential())))
                .signingX509Credentials(c -> c.add(createSigningCredential()))
                .assertionConsumerServiceBinding(Saml2MessageBinding.POST)
                .build();
        return new InMemoryRelyingPartyRegistrationRepository(registration);
    }

    private Saml2X509Credential createSigningCredential() {
        try {
            // Load your private key
            InputStream keyInputStream = getClass().getResourceAsStream("/certs/sp-private-key.pem");
            byte[] keyBytes = keyInputStream.readAllBytes();
            String keyString = new String(keyBytes)
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] decodedKey = Base64.getDecoder().decode(keyString);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

            // Load your certificate
            InputStream certInputStream = getClass().getResourceAsStream("/certs/sp-certificate.pem");
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(certInputStream);

            return new Saml2X509Credential(privateKey, certificate, Saml2X509Credential.Saml2X509CredentialType.SIGNING);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create signing credential", e);
        }
    }

    private Saml2X509Credential createVerificationCredential() {
        try {
            InputStream certInputStream = getClass().getResourceAsStream("/certs/sp-certificate.pem");
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(certInputStream);
            return new Saml2X509Credential(certificate, Saml2X509Credential.Saml2X509CredentialType.VERIFICATION);
        } catch (CertificateException e) {
            throw new RuntimeException("Failed to create verification credential", e);
        }
    }
}
