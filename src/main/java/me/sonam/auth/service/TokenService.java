package me.sonam.auth.service;

import me.sonam.auth.util.JwtPath;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.util.Map;

@Service
public class TokenService {
    private static final Logger LOG = LoggerFactory.getLogger(TokenService.class);

    @Value("${auth-server.root}${auth-server.oauth2token.path}${auth-server.oauth2token.params:}")
    private String oauth2TokenEndpoint;

    @Value("${user-rest-service.root}${user-rest-service.userByAuthid}")
    private String userByAuthIdEp;

    @Autowired
    private JwtPath jwtPath;

    private WebClient.Builder webClientBuilder;

    private RequestCache requestCache;

    public TokenService(WebClient.Builder webClientBuilder, RequestCache requestCache) {
        this.webClientBuilder = webClientBuilder;
        this.requestCache = requestCache;
    }

    /**
     * This will get a accessToken using a grant type of Client Credentials workflow
     * It will send the clientId and clientSecret as base64 encoded as 'clientId:clientSecret'.base64
     * @param accessToken
     * @return
     */

    public Mono<String> getSystemAccessTokenUsingClientCredential(JwtPath.JwtRequest.AccessToken accessToken) {
        LOG.info("get access token using client credentail");
        final StringBuilder oauthEndpointWithScope = new StringBuilder(oauth2TokenEndpoint);

        if (accessToken.getScopes() != null && !accessToken.getScopes().trim().isEmpty()) {
            oauthEndpointWithScope.append("&scope=").append(accessToken.getScopes()).toString();
        }
        LOG.info("sending oauth2TokenEndpointWithScopes: {}", oauthEndpointWithScope);

        WebClient.ResponseSpec responseSpec = webClientBuilder.build().post().uri(oauthEndpointWithScope.toString())
                .headers(httpHeaders -> httpHeaders.setBasicAuth(accessToken.getBase64EncodedClientIdSecret()))
                .accept(MediaType.APPLICATION_JSON)
                .retrieve();

        return responseSpec.bodyToMono(Map.class).map(map -> {
            LOG.debug("response for '{}' is in map: {}", oauth2TokenEndpoint, map);
            if (map.get("access_token") != null) {
                return map.get("access_token").toString();
            }
            else {
                LOG.error("nothing to return");
                return "nothing";
            }
        }).onErrorResume(throwable -> {
            LOG.error("client credentials access token rest call failed: {}", throwable.getMessage());
            String errorMessage = throwable.getMessage();

            if (throwable instanceof WebClientResponseException) {
                WebClientResponseException webClientResponseException = (WebClientResponseException) throwable;
                LOG.error("error body contains: {}", webClientResponseException.getResponseBodyAsString());
                errorMessage = webClientResponseException.getResponseBodyAsString();
            }
            return Mono.error(new RuntimeException(errorMessage));
        });
    }
}
