package saml.sp;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

    @Autowired
    private SamlRequestLoggingFilter samlRequestLoggingFilter;

    private static final String IDP_AUTH_URL = "/api/v1/saml/auth/**";
    private static final String SP_AUTH_URL = "/sso/**";

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().ignoringAntMatchers(IDP_AUTH_URL, SP_AUTH_URL) // Disable CSRF for /sso/*
                .and()
                .authorizeRequests()
                .antMatchers(IDP_AUTH_URL, SP_AUTH_URL).permitAll()
                .anyRequest().authenticated()
                .and()
                .saml2Login()
                .relyingPartyRegistrationRepository(this.relyingPartyRegistrationRepository)
                .loginProcessingUrl("/login/saml2/sso/{registrationId}")
                .defaultSuccessUrl("/home")
                .failureUrl("/sso/login?error")
                .and()
                .logout()
                .logoutSuccessHandler(new CustomLogoutSuccessHandler())
                .logoutSuccessUrl("/sso/logout");

        http.addFilterBefore(samlRequestLoggingFilter, UsernamePasswordAuthenticationFilter.class);
    }

    private static class CustomLogoutSuccessHandler implements LogoutSuccessHandler {
        @Override
        public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
            response.sendRedirect("/sso/logout");
        }
    }
}
