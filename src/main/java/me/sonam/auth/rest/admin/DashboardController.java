package me.sonam.auth.rest.admin;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * When user is redirected from their application to the Authorization server via their OAuth Client
 * application this controller will return the index thymeleaf page.
 */
@Controller
@RequestMapping("/admin")
public class DashboardController {
    private static final Logger LOG = LoggerFactory.getLogger(DashboardController.class);

    @GetMapping("/dashboard")
    public String dashboard() {
        LOG.info("returning dashboard");

        return "admin/dashboard";
    }
}
