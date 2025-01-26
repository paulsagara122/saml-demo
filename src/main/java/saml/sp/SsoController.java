package saml.sp;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Controller
@RequestMapping("/sso")
public class SsoController {

    @GetMapping("/login")
    public String login() {
        return "login";
    }


    @GetMapping("/logout")
    public String logout() {
        return "logout";
    }


    @PostMapping("/saml2/acs")
    public String acs(@RequestParam("SAMLResponse") String samlResponse, Model model) {
        // Decode and parse the SAML response
        byte[] decodedBytes = Base64.getDecoder().decode(samlResponse);
        String decodedResponse = new String(decodedBytes, StandardCharsets.UTF_8);
        System.out.println("decodedResponse: " + decodedResponse);
        // Process the SAML response
        /*Response response = (Response) XMLObjectSupport.unmarshallFromReader(
                XMLObjectProviderRegistrySupport.getParserPool(),
                new StringReader(decodedResponse)
        );*/

        // Validate the response (signature, conditions, issuer, etc.)

        // Extract user attributes and perform authentication
        // If validation is successful, set the authentication
        Authentication authentication = getAuthenticationFromSamlResponse();
        SecurityContextHolder.getContext().setAuthentication(authentication);
        // Redirect to the appropriate page upon successful validation
        return "redirect:/home";
    }

    private Authentication getAuthenticationFromSamlResponse() {
        UserDetails userDetails = FakeUserDetails.createFakeUser();
        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }


    @GetMapping("saml2/authenticate/{registrationId}")
    public String authenticate(@PathVariable String registrationId) {
        // Initiate the SAML authentication process
        // Spring Security SAML will handle the rest
        return "/saml2/authentication-in-progress";
    }
}
