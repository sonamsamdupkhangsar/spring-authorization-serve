package me.sonam.auth.service;

import me.sonam.auth.jpa.entity.ClientOrganization;
import me.sonam.auth.jpa.entity.ClientUser;
import me.sonam.auth.jpa.repo.ClientOrganizationRepository;
import me.sonam.auth.jpa.repo.HClientUserRepository;
import me.sonam.auth.service.exception.AuthorizationException;
import me.sonam.auth.service.exception.BadCredentialsException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
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

    @Value("${user-rest-service.root}${user-rest-service.userByAuthId}")
    private String userEndpoint;

    @Value("${organization-rest-service.root}${organization-rest-service.userExistsInOrganization}")
    private String organizationEndpoint;

    private RequestCache requestCache;
    private WebClient.Builder webClientBuilder;

    @Autowired
    private ClientOrganizationRepository clientOrganizationRepository;

    @Autowired
    private HClientUserRepository clientUserRepository;

    public AuthenticationCallout(WebClient.Builder webClientBuilder, RequestCache requestCache) {
        this.webClientBuilder = webClientBuilder;
        this.requestCache = requestCache;
    }


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        LOG.info("authenticate with username and password");

        final String authenticationId = authentication.getName();
        final String password = authentication.getCredentials().toString();

        LOG.info("authenticationId {}, password: {}", authenticationId, password);

        final String clientId = ClientIdUtil.getClientId(requestCache);
        LOG.info("clientId: {}", clientId);

        LOG.info("authorities: {}, details: {}, credentials: {}", authentication.getAuthorities(),
                authentication.getDetails(), authentication.getCredentials());
        //return getAuth(authentication, clientId).block();

        return checkUserAndClient(authentication, clientId);

      /*  return
                clientOrganizationRepository.findByClientId(clientId)
                //.switchIfEmpty(Mono.error(new AuthorizationException("clientId not in organziation")))
                        .flatMap(clientOrganization -> getUserId(name, clientId).zipWith(Mono.just(clientOrganization))
                                        .flatMap(objects -> userExistInOrganization(objects.getT1(), objects.getT2().getOrganizationId()))
                                        .filter(aBoolean -> aBoolean)
                                        .switchIfEmpty(Mono.error(new AuthorizationException("user does not exists in organization")))

                                        .flatMap(aBoolean -> getAuth(authentication, clientId))).block();
*/

    }

    private UsernamePasswordAuthenticationToken checkUserAndClient(Authentication authentication, String clientId) {
        final String authenticationId = authentication.getName();

        return getUserId(authenticationId).onErrorResume(throwable -> {
                    LOG.error("user not found with authenticationId: {}", authenticationId);
                    return Mono.error(new AuthorizationException("user not found with authenticationId: "+ authenticationId));
                }
                ).flatMap(userId ->
                    checkClientInOrganization(authentication, userId, clientId)
                    .onErrorResume(throwable ->    {
                        LOG.info("clientId is not associated to a organization-id, check if user owns the client-id");

                        return checkClientUserRelationship(userId, clientId, authentication);
                })).block();

        /*
         return checkClientInOrganization(authentication, clientId)
                .onErrorResume(throwable -> {
                    LOG.info("clientId is not associated to a organization-id, check if user owns the client-id");

                    return getUserId(authenticationId)
                            .onErrorResume(throwable1 -> {
                                LOG.error("user does not exist with authenticationId: {}", throwable.getMessage());
                                return Mono.error(new AuthorizationException("user does not exists with authenticationId: "+ authenticationId));
                            })
                            .flatMap(userId -> Mono.just(clientUserRepository.findByClientIdAndUserId(clientId, userId)))
                            .flatMap(clientUserOptional -> {
                                if (clientUserOptional.isPresent()) {
                                   ClientUser clientUser = clientUserOptional.get();
                                   return getAuth(authentication, clientId);
                                }
                                else {
                                   return Mono.error(new AuthorizationException("there is no client-id association with this user-id"));
                                }
                            });
                }).block();
         */
    }

    private Mono<UsernamePasswordAuthenticationToken> checkClientUserRelationship(final UUID userId, final String clientId, final Authentication authentication) {
        /*return getUserId(authenticationId)
                .onErrorResume(throwable -> {
                    LOG.error("user does not exist with authenticationId: {}", throwable.getMessage());
                    return Mono.error(new AuthorizationException("user does not exists with authenticationId: "+ authenticationId));
                })*/
        LOG.info("checking client in ClientUser relationship");
                Optional<ClientUser> clientUserOptional = clientUserRepository.findByClientIdAndUserId(clientId, userId);


                    if (clientUserOptional.isPresent()) {
                        LOG.info("user has clientId relationship");
                        return getAuth(authentication, clientId);
                    }
                    else {
                        LOG.info("client is not found in ClientUser");
                        return Mono.error(new AuthorizationException("there is no client-id association with this user-id"));
                    }

    }

    private Mono<UsernamePasswordAuthenticationToken> checkClientInOrganization(Authentication authentication, UUID userId, String clientId) {
        LOG.info("checking client exists in clientOrganization");

        Optional<ClientOrganization> optionalClientOrganization = clientOrganizationRepository.findByClientId(clientId);
        optionalClientOrganization.ifPresent(clientOrganization -> LOG.info("clientOrganization exists with clientId: {}", clientId));

        if (optionalClientOrganization.isEmpty()) {
            LOG.error("client-id {} not found in clientOrganization", clientId);
           return Mono.error(new AuthorizationException("no clientId " + clientId + " found in ClientOrganization"));
        }

        ClientOrganization clientOrganization = optionalClientOrganization.get();

        //return optionalClientOrganization.map(clientOrganization1 ->
        /*return /*getUserId(authenticationId)
                .flatMap(userId -> */
                //.flatMap(clientOrganizationMono ->
                return userExistInOrganization(userId, clientOrganization.getOrganizationId())

                .filter(aBoolean -> aBoolean)
                .switchIfEmpty(Mono.error(new AuthorizationException("user does not exists in organization")))
                .flatMap(aBoolean -> getAuth(authentication, clientId));//.block();
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


    private Mono<UUID> getUserId(String authenticationId) {
        StringBuilder userByAuthId = new StringBuilder(userEndpoint.replace("{authenticationId}",
                authenticationId));

        LOG.info("make user call out to endpoint: {}", userByAuthId);

        WebClient.ResponseSpec responseSpec = webClientBuilder.build().get().uri(userByAuthId.toString()).retrieve();

        //throws exception on authentication not found return with 401 http status
        return responseSpec.bodyToMono(Map.class).map(map -> {
            LOG.info("user found: {}", map);
            return UUID.fromString(map.get("id").toString());
        }).onErrorResume(throwable -> {
            LOG.error("error on get user by authId to endpoint '{}' with error: {}", userByAuthId,
                    throwable.getMessage());

            if (throwable instanceof WebClientResponseException) {
                WebClientResponseException webClientResponseException = (WebClientResponseException) throwable;
                LOG.error("error body contains: {}", webClientResponseException.getResponseBodyAsString());
                return Mono.error(new AuthorizationException("Failed to get user by authId"));
            }
            else {
                return Mono.error(new AuthorizationException("Failed to get user by authId"));
            }
        });
    }


    private Mono<Boolean> userExistInOrganization(UUID userId, UUID organizationId) {
        StringBuilder userExistsInOrganizationEndpoint = new StringBuilder(
                organizationEndpoint.replace("{organizationId}", organizationId.toString())
                        .replace("{userId}", userId.toString()));

        LOG.info("make userExistsInOrganizationEndpoint call to endpoint: {}", userExistsInOrganizationEndpoint);

        WebClient.ResponseSpec responseSpec = webClientBuilder.build().get()
                .uri(userExistsInOrganizationEndpoint.toString()).retrieve();

        //throws exception if user does not exist in organization
        return responseSpec.bodyToMono(Map.class).map(map -> {
            LOG.info("userExistsInOrganization response: {}, map.get'message': {}", map, map.get("message"));
            LOG.info("map.get(message): {}", map.get("message").equals(true));
            if (map.get("message").equals(true)) {
                LOG.info("return true");
                return true;
            }
            else {
                LOG.info("returni false");
                return false;
            }

        }).onErrorResume(throwable -> {
            LOG.error("error on userExistsInOrganizationEndpoint to endpoint '{}' with error: {}", userExistsInOrganizationEndpoint,
                    throwable.getMessage());

            if (throwable instanceof WebClientResponseException) {
                WebClientResponseException webClientResponseException = (WebClientResponseException) throwable;
                LOG.error("error body contains: {}", webClientResponseException.getResponseBodyAsString());
               return Mono.just(false);
            }
            else {
                return Mono.just(false);
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