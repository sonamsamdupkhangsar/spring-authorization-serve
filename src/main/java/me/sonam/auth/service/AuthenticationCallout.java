package me.sonam.auth.service;

import me.sonam.auth.service.exception.BadCredentialsException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class AuthenticationCallout implements AuthenticationProvider {
    private static final Logger LOG = LoggerFactory.getLogger(AuthenticationCallout.class);

    @Value("${application-rest-service.root}${application-rest-service.client-role}")
    private String applicationClientRoleService;

    @Value("${authentication-rest-service.root}${authentication-rest-service.authenticate}")
    private String authenticateEndpoint;

    private RequestCache requestCache;
    private WebClient.Builder webClientBuilder;

    public AuthenticationCallout(WebClient.Builder webClientBuilder, RequestCache requestCache) {
        this.webClientBuilder = webClientBuilder;
        this.requestCache = requestCache;
    }


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        LOG.info("authenticate with username and password");

        final String name = authentication.getName();
        final String password = authentication.getCredentials().toString();
        final String clientId = ClientIdUtil.getClientId(requestCache);
        LOG.info("clientId: {}", clientId);

        LOG.info("authorities: {}, details: {}, credentials: {}", authentication.getAuthorities(),
                authentication.getDetails(), authentication.getCredentials());
        Mono<UsernamePasswordAuthenticationToken> mono = getAuth(authentication, clientId);
        return mono.flatMap( usernamePasswordAuthenticationToken ->
                getRoles(authentication.getPrincipal().toString(), clientId))
                .flatMap(map -> {
                    final List<GrantedAuthority> grantedAuths = new ArrayList<>();
                    grantedAuths.add(new SimpleGrantedAuthority("ROLE_USER"));
                    final UserDetails principal = new User(name, password, grantedAuths);
                    LOG.info("returning using custom authenticator");
                    final Authentication auth = new UsernamePasswordAuthenticationToken(principal, password, grantedAuths);
                    return Mono.just(auth);
                }).block();

        //OAuth2AuthenticatedPrincipal oAuth2AuthenticatedPrincipal = (OAuth2AuthenticatedPrincipal) authentication;

       /* if (name.equals("user1") && password.equals("password")) {
            final List<GrantedAuthority> grantedAuths = new ArrayList<>();
            grantedAuths.add(new SimpleGrantedAuthority("ROLE_USER"));
            final UserDetails principal = new User(name, password, grantedAuths);
            LOG.info("returning using custom authenticator");
            final Authentication auth = new UsernamePasswordAuthenticationToken(principal, password, grantedAuths);
            return auth;
        } else {
            throw new BadCredentialsException("Bad credentials");
        }*/
    }

    private Mono<UsernamePasswordAuthenticationToken> getAuth(Authentication authentication, String clientId) {
        String password = authentication.getCredentials().toString();

        WebClient.ResponseSpec responseSpec = webClientBuilder.build().post().uri(authenticateEndpoint).bodyValue(
                        Map.of("authenticationId", authentication.getPrincipal().toString(),
                                "password", password,
                                "clientId", clientId))
                .retrieve();

        //throws exception on authentication not found return with 401 http status
        return responseSpec.bodyToMono(String.class).flatMap(string -> {
                    LOG.info("authentication response: {}", string);
                    return Mono.just(new UsernamePasswordAuthenticationToken(authentication.getPrincipal(),
                            password, new ArrayList<>()));
                })
                .onErrorResume(throwable -> {
            LOG.error("error on authentication-rest-service call {}", throwable.getMessage());

            if (throwable instanceof WebClientResponseException) {
                WebClientResponseException webClientResponseException = (WebClientResponseException) throwable;
                LOG.error("error body contains: {}", webClientResponseException.getResponseBodyAsString());
                //return Mono.error(new Exception("authentication failed: "+webClientResponseException.getResponseBodyAsString()));
                return Mono.error(new BadCredentialsException("Bad credentials"));
            }
            else {
               // return Mono.error(new Exception("authentication failed with error: " +throwable.getMessage()));
                return Mono.error(new BadCredentialsException("Bad credentials"));
            }
        });
    }

    private Mono<Map> getRoles(String authenticationId, String clientId) {
        LOG.info("get roles from application-rest-service for authenticationId: {}, clientId: {}",
            authenticationId, clientId);

        WebClient.ResponseSpec responseSpec = webClientBuilder.build().get().uri(
                        applicationClientRoleService.replace("{clientId}", clientId)
                                .replace("{authenticationId}", authenticationId))
                .retrieve();
        return responseSpec.bodyToMono(Map.class).map(clientUserRole -> {
            LOG.info("got role: {}", clientUserRole);
            return clientUserRole;
        }).onErrorResume(throwable -> {
            LOG.error("application rest call failed: {}", throwable.getMessage());
            if (throwable instanceof WebClientResponseException) {
                WebClientResponseException webClientResponseException = (WebClientResponseException) throwable;
                LOG.error("error body contains: {}", webClientResponseException.getResponseBodyAsString());
            }
            Map<String, Object> map = new HashMap<>();
            map.put("userRole", "");
            map.put("groupNames", "");
            return Mono.just(map);
        });
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}