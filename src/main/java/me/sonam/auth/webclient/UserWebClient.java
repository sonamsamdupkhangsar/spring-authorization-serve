package me.sonam.auth.webclient;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

public class UserWebClient {
    private static final Logger LOG = LoggerFactory.getLogger(UserWebClient.class);

    private final WebClient.Builder webClientBuilder;

    private String userByAuthIdEp;

    public UserWebClient(WebClient.Builder webClientBuilder,
                         String userByAuthIdEp) {
        this.webClientBuilder = webClientBuilder;
        this.userByAuthIdEp = userByAuthIdEp;
    }

    public Mono<Map<String, String>> getUserByAuthenticationId(String authenticationId) {
        final String userInfoEndpoint = userByAuthIdEp.replace("{authenticationId}", authenticationId);
        LOG.info("making a call to user endpoint: {}", userInfoEndpoint);

        WebClient.ResponseSpec responseSpec = webClientBuilder.build().get().uri(userInfoEndpoint)
                .retrieve();

        return responseSpec.bodyToMono(new ParameterizedTypeReference<Map<String, String>>() {
        }).onErrorResume(throwable -> {
            LOG.error("error on getting user info from user-rest-service endpoint '{}' with error: {}",
                    userInfoEndpoint, throwable.getMessage());
            return Mono.error(new RuntimeException("user info call failed, error: " + throwable.getMessage()));
        });
    }


}
