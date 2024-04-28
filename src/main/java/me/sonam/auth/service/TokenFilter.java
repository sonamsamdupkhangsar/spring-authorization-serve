package me.sonam.auth.service;

import me.sonam.auth.util.JwtPath;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * this token filter will be invoked automatically by the webclient for intercepting request
 * to add a access-token by making a client-credential flow http call.
 * Don't add it manually to a webclient to avoid getting calling twice.
 */
@Service
public class TokenFilter {
    private static final Logger LOG = LoggerFactory.getLogger(TokenFilter.class);

    @Value("${auth-server.root}${auth-server.oauth2token.path}${auth-server.oauth2token.params:}")
    private String oauth2TokenEndpoint;

    @Value("${user-rest-service.root}${user-rest-service.userByAuthId}")
    private String userByAuthIdEp;

    @Autowired
    private JwtPath jwtPath;

    private WebClient.Builder webClientBuilder;

    private RequestCache requestCache;
    @Value("${auth-server.oauth2token.path:}")
    private String accessTokenPath;

    public TokenFilter(WebClient.Builder webClientBuilder, RequestCache requestCache) {
        this.webClientBuilder = webClientBuilder;
        this.requestCache = requestCache;
    }

    public ExchangeFilterFunction renewTokenFilter() {
        return (request, next) -> {
            LOG.debug("request.path: {}", request.url().getPath());
            if (request.url().getPath().equals(accessTokenPath)) {
                LOG.debug("no need to request access token when going to that path: {}", request.url().getPath());
                ClientRequest clientRequest = ClientRequest.from(request).build();
                return next.exchange(clientRequest);
            }
            else {
                LOG.info("going thru jwt request ") ;
                for (JwtPath.JwtRequest jwt : jwtPath.getJwtRequest()) {
                    LOG.debug("jwt.out: {}", jwt.getOut());
                    String[] outMatches = jwt.getOut().split(",");
                    for (String outPath : outMatches) {
                        LOG.info("outPath: {}", outPath);
                        if (request.url().getPath().matches(outPath.trim())) {
                            LOG.info("path {} matches with outbound request matches: {}",
                                    outPath, request.url().getPath());
                            LOG.info("make a token request");

                            final StringBuilder oauthEndpointWithScope = new StringBuilder(oauth2TokenEndpoint);

                            if (jwt.getAccessToken().getScopes() != null && !jwt.getAccessToken().getScopes().trim().isEmpty()) {
                                oauthEndpointWithScope.append("&scope=").append(jwt.getAccessToken().getScopes());
                            }


                            return getAccessToken(oauthEndpointWithScope.toString(), jwt.getAccessToken().getBase64EncodedClientIdSecret())
                                    .flatMap(accessToken -> {

                                        LOG.info("get accessToken: {}", accessToken);
                                        ClientRequest clientRequest = ClientRequest.from(request)
                                                .headers(headers -> {
                                                    headers.set(HttpHeaders.ORIGIN, request.headers().getFirst(HttpHeaders.ORIGIN));
                                                    headers.setBearerAuth(accessToken);
                                                    LOG.info("added access-token to http header");
                                                }).build();
                                        return Mono.just(clientRequest);
                                    }).flatMap(clientRequest -> next.exchange(clientRequest));
                        }
                    }
                }

                LOG.info("no outbound path match found");
                ClientRequest filtered = ClientRequest.from(request)
                        .build();
                return next.exchange(filtered);
            }
        };
    }

    private Mono<String> getAccessToken(final String oauthEndpoint, final String base64EncodeClientIdSecret) {
        LOG.info("making a access-token request to endpoint: {}",oauthEndpoint);
        WebClient.ResponseSpec responseSpec = webClientBuilder.build().post().uri(oauthEndpoint)
                .headers(httpHeaders -> httpHeaders.setBasicAuth(base64EncodeClientIdSecret))
                .accept(MediaType.APPLICATION_JSON)
                .retrieve();

        return responseSpec.bodyToMono(Map.class).map(map -> {
            LOG.debug("response for '{}' is in map: {}", oauthEndpoint, map);
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
