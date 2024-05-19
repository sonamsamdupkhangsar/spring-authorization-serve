package me.sonam.auth.rest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

/**
 * When user is redirected from their application to the Authorization server via their OAuth Client
 * application this controller will return the index thymeleaf page.
 */
@Controller
public class IndexController {
    private static final Logger LOG = LoggerFactory.getLogger(IndexController.class);

    @Value("${authzmanager}")
    private String authzManagerUrl;

    @GetMapping("/")
    public String index(Model model) {
        LOG.info("returning index");

        model.addAttribute("authzmanager", authzManagerUrl);
        return "index";
    }
}
