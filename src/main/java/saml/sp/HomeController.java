package saml.sp;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    @GetMapping("/")
    public String home(Model model, @AuthenticationPrincipal User user) {
        if (user != null) {
            model.addAttribute("username", user.getUsername());
        }
        return "home";
    }

    @GetMapping("/login")
    public String login() {
        return "redirect:/saml2/authenticate/your-sp";
    }
}
