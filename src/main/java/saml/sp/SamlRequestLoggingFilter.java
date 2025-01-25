package saml.sp;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class SamlRequestLoggingFilter extends OncePerRequestFilter {

    private final AntPathRequestMatcher requestMatcher = new AntPathRequestMatcher("/login/saml2/sso/**", "POST");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (requestMatcher.matches(request)) {
            // Log the request parameters
            System.out.println("SAML Authentication Request: " + request.getParameter("SAMLRequest"));
            System.out.println("RelayState: " + request.getParameter("RelayState"));
        }

        filterChain.doFilter(request, response);
    }
}
