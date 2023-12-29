package me.sonam.auth.rest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

/**
 * When user wants to manage their OAuth client this controller will return a login
 * thymeleaf page.
 */
@Controller
public class ClientManageLoginController {
    private static final Logger LOG = LoggerFactory.getLogger(ClientManageLoginController.class);

    @GetMapping("/manage/login")
    public String login() {
        LOG.info("returning client manage login");

        return "login";
    }


}
