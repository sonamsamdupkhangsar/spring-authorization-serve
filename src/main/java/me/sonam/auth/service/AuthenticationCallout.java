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
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.util.*;

/**
 * This class is used for making authentication callout to external authentication-rest-service
 * for authenticating username and password.
 */
@Service
public class AuthenticationCallout implements AuthenticationProvider {
    private static final Logger LOG = LoggerFactory.getLogger(AuthenticationCallout.class);

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
        //Mono<UsernamePasswordAuthenticationToken> mono = getAuth(authentication, clientId);
        return getAuth(authentication, clientId).block();
        /*return mono.flatMap( usernamePasswordAuthenticationToken ->
                        getUserRoleForClientId(authentication.getPrincipal().toString(), clientId))
                .flatMap(map -> {
                    final List<GrantedAuthority> grantedAuths = new ArrayList<>();
                    grantedAuths.add(new SimpleGrantedAuthority("ROLE_USER"));

                    final UserDetails principal = new User(name, password, grantedAuths);
                    LOG.info("returning using custom authenticator");
                    final Authentication auth = new UsernamePasswordAuthenticationToken(principal, password, grantedAuths);
                    return Mono.just(auth);
                }).block();*/
    }

    private Mono<UsernamePasswordAuthenticationToken> getAuth(Authentication authentication, String clientId) {
        String password = authentication.getCredentials().toString();

        LOG.info("make authentication call out to endpoint: {}", authenticateEndpoint);

        WebClient.ResponseSpec responseSpec = webClientBuilder.build().post().uri(authenticateEndpoint).bodyValue(
                        Map.of("authenticationId", authentication.getPrincipal().toString(),
                                "password", password,
                                "clientId", clientId))
                .retrieve();

        //throws exception on authentication not found return with 401 http status
        return responseSpec.bodyToMono(Map.class).map(map -> {
            LOG.info("authentication response for roles: {}", map);

            final List<GrantedAuthority> grantedAuths = new ArrayList<>();

            if (map.get("roleNames") != null) {
               String roleList = map.get("roleNames").toString();
               roleList = roleList.replace("[", "");
               roleList = roleList.replace("]", "");

               LOG.debug("go thru each roleName from list and add to grantedAuths: {}", roleList);
               String[] roles = roleList.split(",");
               for(String role: roles) {
                   LOG.info("add role: {}", role);
                   grantedAuths.add(new SimpleGrantedAuthority(role));
               }
            }
            final UserDetails principal = new User(authentication.getName(), password, grantedAuths);

            LOG.info("returning using custom authenticator with grantedAuths added: {}", grantedAuths);
            return new UsernamePasswordAuthenticationToken(principal, password, grantedAuths);

        }).onErrorResume(throwable -> {
            LOG.error("error on authentication-rest-service to endpoint '{}' with error: {}", authenticateEndpoint,
                    throwable.getMessage());

            if (throwable instanceof WebClientResponseException) {
                WebClientResponseException webClientResponseException = (WebClientResponseException) throwable;
                LOG.error("error body contains: {}", webClientResponseException.getResponseBodyAsString());
                return Mono.error(new BadCredentialsException("Bad credentials"));
            }
            else {
                return Mono.error(new BadCredentialsException("Bad credentials"));
            }
        });
    }

   /* private Mono<Map> getRolesOld(String authenticationId, String clientId) {
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
            LOG.error("application rest call failed to endpoint '{}' with error {}", applicationClientRoleService,
                    throwable.getMessage());
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
*/


    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}