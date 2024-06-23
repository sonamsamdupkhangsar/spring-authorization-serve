package me.sonam.auth.webclient;

import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

import static reactor.core.publisher.Mono.just;

public class TokenMediatorWebClient {
    private static final Logger LOG = LoggerFactory.getLogger(TokenMediatorWebClient.class);

    private String tokenMediatorEndpoint;
    private WebClient.Builder webClientBuilder;

    public TokenMediatorWebClient(WebClient.Builder webClientBuilder, String tokenMediatorEndpoint) {
        this.webClientBuilder = webClientBuilder;
        this.tokenMediatorEndpoint = tokenMediatorEndpoint;
    }

    public Mono<Map> saveClientInTokenMediator(String accessToken, String clientId, String password) {
        LOG.info("save client in tokenMediator");
        WebClient.ResponseSpec responseSpec = webClientBuilder.build().put().uri(tokenMediatorEndpoint)
                .headers(httpHeaders -> httpHeaders.setBearerAuth(accessToken))
                .bodyValue(Map.of("clientId", clientId, "clientSecret", password))
                .accept(MediaType.APPLICATION_JSON)
                .retrieve();
        return responseSpec.bodyToMono(Map.class).
                onErrorResume(throwable -> {LOG.error("failed to save clientId and clientSecret in token-mediator: {}", throwable.getMessage());
                    return just(Map.of("error", "failed to save client in token-mediator"));
                });
    }

    public Mono<Map> deleteClientFromTokenMediator(String accessToken, String clientId) {
        LOG.info("delete client from tokenMediator with accessToken: {}", accessToken);
        String deleteTokenEndpoint = new StringBuilder(tokenMediatorEndpoint).append("/").append(clientId).toString();

        WebClient.ResponseSpec responseSpec = webClientBuilder.build().delete().uri(deleteTokenEndpoint)
                .headers(httpHeaders -> httpHeaders.setBearerAuth(accessToken))
                .accept(MediaType.APPLICATION_JSON)
                .retrieve();
        return responseSpec.bodyToMono(Map.class)
                .onErrorResume(throwable -> {
                    LOG.error("failed to delete clientId in token-mediator: {}", throwable.getMessage());
                    return just(Map.of("error", "failed to delete client in token-mediator"));
                });
    }
}
