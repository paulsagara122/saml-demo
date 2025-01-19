package saml.sp;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.credentials.Saml2X509Credential;
import org.springframework.security.saml2.credentials.Saml2X509Credential.Saml2X509CredentialType;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

@EnableWebSecurity
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/", "/login").permitAll()
                .anyRequest().authenticated()
                .and()
                .saml2Login()
                .loginPage("/login");
    }

    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() throws Exception {
        X509Certificate certificate = loadCertificate("saml/certificate.crt");
        Saml2X509Credential verificationCredential = new Saml2X509Credential(certificate, Saml2X509CredentialType.VERIFICATION);

        RelyingPartyRegistration registration = RelyingPartyRegistration
                .withRegistrationId("your-sp")
                .assertingPartyDetails(party -> party
                        .entityId("https://localhost:9090/entity-id")
                        .singleSignOnServiceLocation("http://localhost:9090/saml")
                        .wantAuthnRequestsSigned(true)
//                        .verificationX509Credentials(creds -> creds.add(verificationCredential))
                )
                .build();

        return new InMemoryRelyingPartyRegistrationRepository(registration);
    }

    private X509Certificate loadCertificate(String path) throws Exception {
        try (InputStream inputStream = new ClassPathResource(path).getInputStream()) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(inputStream);
        }
    }
}
