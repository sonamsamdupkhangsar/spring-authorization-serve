package me.sonam.auth.webclient;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

public class AccountWebClient {
    private static final Logger LOG = LoggerFactory.getLogger(AccountWebClient.class);

    private final WebClient.Builder webClientBuilder;

    private String emailUserName;
    private String emailMySecret;
    private String emailActiveLink;
    private String validateEmailLoginSecret;
    private String updatePassword;

    public AccountWebClient(WebClient.Builder webClientBuilder,
                            String emailUserName, String emailMySecret, String emailActiveLink,
                            String validateEmailLoginSecret, String updatePassword) {
        this.webClientBuilder = webClientBuilder;
        this.emailUserName = emailUserName;
        this.emailMySecret = emailMySecret;
        this.emailActiveLink = emailActiveLink;
        this.validateEmailLoginSecret = validateEmailLoginSecret;
        this.updatePassword = updatePassword;
    }

    public Mono<String> emailAccountActivationLink(String email) {
        emailActiveLink = emailActiveLink.replace("{email}", email);
        LOG.info("email using endpoint: {}", emailActiveLink);

        WebClient.ResponseSpec responseSpec = webClientBuilder.build().put().uri(emailActiveLink)
                .retrieve();
        return responseSpec.bodyToMono(String.class);
    }

    public Mono<String> emailMySecret(String email) {
        emailMySecret = emailMySecret.replace("{email}", email);
        LOG.info("email '{}' using endpoint: {}", email, emailMySecret);

        WebClient.ResponseSpec responseSpec = webClientBuilder.build().put().uri(emailMySecret)
                .retrieve();
        return responseSpec.bodyToMono(String.class).onErrorResume(throwable -> {
            LOG.error("failed to call email my secret endpoint", throwable);
            return Mono.error(throwable);
        });
    }

    public Mono<Map<String, String>> validateEmailLoginSecret(String email, String secret) {
        LOG.info("call validate email login secret using account-rest-service");

        String endpoint = validateEmailLoginSecret.replace("{email}", email).replace("{secret}", secret);
        LOG.info("validate secret using endpoint: {}", endpoint);

        WebClient.ResponseSpec responseSpec = webClientBuilder.build().get().uri(endpoint)
                .retrieve();
        return responseSpec.bodyToMono(new ParameterizedTypeReference<Map<String, String>>() {});
    }

    public Mono<Map<String, String>> updateAuthenticationPassword(String email, String secret, String password) {
        LOG.info("update password using account-rest-service {}", updatePassword);



        WebClient.ResponseSpec responseSpec = webClientBuilder.build().put().uri(updatePassword)
                .bodyValue(Map.of("email", email, "secret", secret, "password", password))
                .retrieve();
        return responseSpec.bodyToMono(new ParameterizedTypeReference<>() {});
    }

    public Mono<Map<String, String>> emailUsername(String email) {
        LOG.info("email username using account-rest-service");

        String endpoint = emailUserName.replace("{email}", email);
        LOG.info("email username endpoint: {}", endpoint);

        WebClient.ResponseSpec responseSpec = webClientBuilder.build().put().uri(endpoint)
                .retrieve();
        return responseSpec.bodyToMono(new ParameterizedTypeReference<>() {});
    }
}
