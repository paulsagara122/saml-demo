package saml.sp;

import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.stereotype.Component;

@Component
public class MySamlServiceProvider implements RelyingPartyRegistrationRepository {

    @Override
    public RelyingPartyRegistration findByRegistrationId(String registrationId) {
        return RelyingPartyRegistration
                .withRegistrationId("my-saml-service-provider")
                .entityId("service-provider-entity-id")
                .assertingPartyDetails(details ->
                        details.entityId("http://localhost:9090/sso")
                                .singleSignOnServiceLocation("http://localhost:9090/sso")
                                .wantAuthnRequestsSigned(false))
                .build();
    }
}
