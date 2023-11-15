package me.sonam.auth.rest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class LoginController {
    private static final Logger LOG = LoggerFactory.getLogger(LoginController.class);

    @GetMapping("/login")
    public String login() {
        LOG.info("returning login");

        return "login";
    }

    @GetMapping("/forgotPassword")
    public String forgotPassword() {
        LOG.info("returning forgotPassword");
        return "forgotPassword";
    }

    @GetMapping("/forgotUsername")
    public String forgotUsername() {
        LOG.info("returning forgotUsername");
        return "forgotUsername";
    }

    @PostMapping("/forgot/emailUsername")
    public String emailUsername(String emailAddress, Model model) {
        LOG.info("email username for email: {}", emailAddress);
        model.addAttribute("message", "Your username has been sent to your email address.");
        return "forgotUsername";
    }

    @PostMapping("/forgot/changePassword")
    public String passwordChange(String emailAddress, Model model) {
        LOG.info("password change for email: {}", emailAddress);
        model.addAttribute("message", "Check your email for changing your password.");
        return "forgotPassword";
    }

}
