package me.sonam.auth.rest;

import me.sonam.auth.service.exception.BadCredentialsException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * This controller is for returning the forgotUsername and forgotPassword html Thymeleaf page.
 * When user request their username on 'forgotUsername' page it will call {@link #emailUsername(String, Model)} method.
 * When user request password change on 'forgotPassword' page it will call {@link #passwordChange(String, Model)} method.
 * Permissions need to be set in the {@link me.sonam.auth.config.JwtUserInfoMapperSecurityConfig
 * #defaultSecurityFilterChain(HttpSecurity)} method for each path.
 */
@Controller
public class ForgotUsernameController {
    private static final Logger LOG = LoggerFactory.getLogger(ForgotUsernameController.class);

    @Value("${account-rest-service.root}${account-rest-service.emailUsername}")
    private String emailUserName;

    @Value("${account-rest-service.root}${account-rest-service.emailMySecret}")
    private String emailMySecret;

    private WebClient.Builder webClientBuilder;
    public ForgotUsernameController(WebClient.Builder webClientBuilder) {
        this.webClientBuilder = webClientBuilder;
    }

    @GetMapping("/forgotUsername")
    public String forgotUsername() {
        LOG.info("returning forgotUsername");
        return "forgotUsername";
    }

    @GetMapping("/forgotPassword")
    public String forgotPassword() {
        LOG.info("returning forgotPassword");
        return "forgotPassword";
    }

    @PostMapping("/forgot/emailUsername")
    public String emailUsername(String emailAddress, Model model) {
        LOG.info("email username for email: {}", emailAddress);

        StringBuilder emailUsernameEndpoint = new StringBuilder(emailUserName.replace("{email}",
                emailAddress));
      return  accountRestServiceCall(emailUsernameEndpoint.toString()).
              flatMap(s -> {
            LOG.info("add message attribute");
            model.addAttribute("message", "Your username has been sent to your email address.");
            return Mono.just("forgotUsername");
        }).onErrorResume(throwable -> {
            LOG.error("error on calling emailMyUsername endpoint '{}' with error: {}", emailUsernameEndpoint,
                    throwable.getMessage());

            if (throwable instanceof WebClientResponseException) {
                WebClientResponseException webClientResponseException = (WebClientResponseException) throwable;
                Map<String, String> map = webClientResponseException.getResponseBodyAs(Map.class);
                LOG.error("error: {}", map.get("error"));
                //set model error attribute to present back to user
                model.addAttribute("error", map.get("error"));
            } else {
                //set model error attribute to present back to user
                model.addAttribute("error", "Failed calling account-rest-service for emailMySecret");
            }
            return Mono.just("forgotUsername");
        }).block();
    }

    /**
     * this is called to change password by user when they don't remember it anymore.
     * This will call account-rest-service method to start the process for password change.
     * Account-rest-service will create a accesscode for password change process and send
     * them a link with the code to click in the email.
     * @param authenticationId
     * @param model
     * @return
     */
    @PostMapping("/forgot/changePassword")
    public String passwordChange(String authenticationId, Model model) {
        LOG.info("password change for email: {}", authenticationId);

        StringBuilder emailMySecretEndpoint = new StringBuilder(emailMySecret.replace("{authenticationId}",
                authenticationId));

        return accountRestServiceCall(emailMySecretEndpoint.toString())
                .flatMap(s -> {
            LOG.info("add message attribute");
            model.addAttribute("message", "Check your email for changing your password.");
            return Mono.just("forgotPassword");
        }).onErrorResume(throwable -> {
            LOG.error("error on calling emailMySecret endpoint '{}' with error: {}", emailMySecretEndpoint,
                    throwable.getMessage());

            if (throwable instanceof WebClientResponseException) {
                WebClientResponseException webClientResponseException = (WebClientResponseException) throwable;
                Map<String, String> map = webClientResponseException.getResponseBodyAs(Map.class);
                LOG.error("error: {}", map.get("error"));

                //set model error attribute to present back to user
                model.addAttribute("error", map.get("error"));
            } else {
                //set model error attribute to present back to user
                model.addAttribute("error", "Failed calling account-rest-service for emailMySecret");
            }
            LOG.info("return to the forgotPassword template page");
            return Mono.just("forgotPassword");
        }).block();
    }

    private Mono<String> accountRestServiceCall(String endpoint) {
        LOG.info("make user call out to endpoint: {}", endpoint);

        WebClient.ResponseSpec responseSpec = webClientBuilder.build().put().uri(endpoint)
                    .retrieve();

        //throws exception on authentication not found return with 401 http status
        return responseSpec.bodyToMono(Map.class).map(map -> {
            LOG.info("account-rest-service response: {}", map);
            return map.get("message").toString();
        });
    }
}
