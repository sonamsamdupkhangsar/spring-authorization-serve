package me.sonam.auth.service;

import com.nimbusds.jose.util.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

//@Component
public class AuthenticationCallout implements AuthenticationProvider {
    private static final Logger LOG = LoggerFactory.getLogger(AuthenticationCallout.class);

    @Autowired
    private JpaOAuth2AuthorizationService jpaOAuth2AuthorizationService;

    private WebClient.Builder webClientBuilder;

    public AuthenticationCallout(WebClient.Builder webClientBuilder) {
        this.webClientBuilder = webClientBuilder;
    }


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        LOG.info("authenticate with username and password");

        final String name = authentication.getName();
        final String password = authentication.getCredentials().toString();


        LOG.info("authorities: {}, details: {}, credentials: {}", authentication.getAuthorities(),
                authentication.getDetails(), authentication.getCredentials());
        //OAuth2AuthenticatedPrincipal oAuth2AuthenticatedPrincipal = (OAuth2AuthenticatedPrincipal) authentication;

        if (name.equals("user") && password.equals("password")) {
            final List<GrantedAuthority> grantedAuths = new ArrayList<>();
            grantedAuths.add(new SimpleGrantedAuthority("ROLE_USER"));
            final UserDetails principal = new User(name, password, grantedAuths);
            LOG.info("returning using custom authenticator");
            final Authentication auth = new UsernamePasswordAuthenticationToken(principal, password, grantedAuths);
            return auth;
        } else {
            return null;
        }
    }

/*    private Mono<Authentication> getAuth(Authentication authentication) {
        String password = authentication.getCredentials().toString();

        WebClient.ResponseSpec responseSpec = webClientBuilder.build().post().bodyValue(
                        Map.of("authenticationId", authentication.getPrincipal(),
                                "password", password,
                                "clientId", "12"))
                .retrieve();

        return responseSpec.bodyToMono(Map.class).flatMap(map -> {
            LOG.info("authentication response {}", map);
            return Mono.just(new UsernamePasswordAuthenticationToken(authentication.getPrincipal(),
                    password, new ArrayList<>()));
        }).onErrorResume(throwable -> {
            LOG.error("error on authentication-rest-service call {}", throwable);

            if (throwable instanceof WebClientResponseException) {
                WebClientResponseException webClientResponseException = (WebClientResponseException) throwable;
                LOG.error("error body contains: {}", webClientResponseException.getResponseBodyAsString());
                return Mono.error(new Exception("authentication failed: "+webClientResponseException.getResponseBodyAsString()));
            }
            else {
                return Mono.error(new Exception("authentication failed with error: " +throwable.getMessage()));
            }
        });
    }*/
    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
