package me.sonam.auth.service;

import me.sonam.auth.jpa.entity.ClientOrganization;
import me.sonam.auth.jpa.entity.ClientUser;
import me.sonam.auth.jpa.repo.ClientOrganizationRepository;
import me.sonam.auth.jpa.repo.HClientUserRepository;
import me.sonam.auth.service.exception.BadCredentialsException;
import me.sonam.auth.util.UserId;
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
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
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

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Value("${authzmanager-id}")
    private UUID authzManagerId;

    final String ROLES = "roles";

  /*  public AuthenticationCallout(String authenticateEndpoint, String userEndpoint, String organizationEndpoint,
                                 RequestCache requestCache, WebClient.Builder webClientBuilder,
                                 ClientOrganizationRepository clientOrganizationRepository,
                                 HClientUserRepository clientUserRepository) {
        this.authenticateEndpoint = authenticateEndpoint;
        this.userEndpoint = userEndpoint;
        this.organizationEndpoint = organizationEndpoint;
        this.requestCache = requestCache;
        this.webClientBuilder = webClientBuilder;
        this.clientOrganizationRepository = clientOrganizationRepository;
        this.clientUserRepository = clientUserRepository;
    }*/

    public AuthenticationCallout(WebClient.Builder webClientBuilder, RequestCache requestCache) {
        this.webClientBuilder = webClientBuilder;
        this.requestCache = requestCache;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        LOG.info("authenticate with username and password");

        var requestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        LOG.info("requestAttributes: {}", requestAttributes);

        var request = requestAttributes.getRequest();
        enum LoginType {
            OAUTH_LOGIN, CLIENT_MANAGE_LOGIN
        }

        var loginType =  requestAttributes.getRequest().getParameter("manage");
        LOG.info("manage request value: {}", loginType);
        LOG.info("request getRequestURI info: {}", request.getRequestURI());

        if (loginType != null && loginType.equals(LoginType.CLIENT_MANAGE_LOGIN.name())) {
            LOG.info("do a clientManageLogin when value is {}", LoginType.CLIENT_MANAGE_LOGIN);
            return clientManageLogin(authentication);
        }

        final String authenticationId = authentication.getName();
        final String password = authentication.getCredentials().toString();

        LOG.info("authenticationId {}, password: {}", authenticationId, password);

         String clientId = ClientIdUtil.getClientId(requestCache);
         LOG.info("clientId: {}", clientId);
         if (clientId == null || clientId.equals("")) {
             LOG.error("client id not found");
             throw new BadCredentialsException("clientId not found in request cache");
         }

        LOG.info("authorities: {}, details: {}, credentials: {}", authentication.getAuthorities(),
                authentication.getDetails(), authentication.getCredentials());
         LOG.info("get registeredClient from clientId: {}", clientId);
         RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
         UUID clientUuidId = UUID.fromString(registeredClient.getId());
         LOG.info("got clientUuid: {}", clientUuidId);
        return checkUserAndClient(authentication, clientUuidId).block();

    }

    private Authentication clientManageLogin(Authentication authentication) {
        LOG.info("clientManage login, return dummy authentication object");
        final List<GrantedAuthority> grantedAuths = new ArrayList<>();
        final UserDetails principal = new User(authentication.getName(), authentication.getCredentials().toString(), grantedAuths);

        LOG.info("returning using custom authenticator with grantedAuths added: {}", grantedAuths);
        return new UsernamePasswordAuthenticationToken(principal, authentication.getCredentials().toString(), grantedAuths);
    }

    private Mono<UsernamePasswordAuthenticationToken> checkUserAndClient(Authentication authentication, UUID clientId) {
        final String authenticationId = authentication.getName();
        LOG.info("check user and client relationship");

        return getUserId(authenticationId).onErrorResume(throwable -> {
            LOG.error("failed to make get user by authId call: {}", throwable.getMessage());
            if (throwable instanceof WebClientResponseException) {
                WebClientResponseException webClientResponseException = (WebClientResponseException) throwable;
                LOG.error("error body contains: {}", webClientResponseException.getResponseBodyAsString());
            }

            LOG.error("user not found with authenticationId: {}", authenticationId, throwable);
            return Mono.error(new BadCredentialsException("user not found with authenticationId: "+ authenticationId));
        }
        ).flatMap(userId ->
            checkClientInOrganization(authentication, userId, clientId)
                    .switchIfEmpty(checkClientUserRelationship(userId, clientId, authentication))

                    .onErrorResume(throwable -> {
                        LOG.error("clientId is not associated to a organization-id, check if user owns the client-id");

                        return Mono.error(throwable);
                        //return checkClientUserRelationship(userId, clientId, authentication);
                    })
        );
    }

    private Mono<UsernamePasswordAuthenticationToken> checkClientUserRelationship(final UUID userId, final UUID clientId, final Authentication authentication) {
        LOG.info("checking userId {} and clientId {} in ClientUser relationship", userId, clientId);

        Optional<ClientUser> clientUserOptional = clientUserRepository.findByClientIdAndUserId(clientId, userId);

        if (clientUserOptional.isPresent()) {
            LOG.info("user has clientId relationship");
            return getAuth(authentication, clientId);
        }
        else {
            if (authzManagerId.equals(clientId)) {
                LOG.info("clientId is for authzmanager, create user-authzmanager client relationship");
                clientUserRepository.save(new ClientUser(clientId, userId));

                return getAuth(authentication, clientId);
            }
            else {
                LOG.info("client-id has no relationship with user-id, user is accessing the authzmanager app");
                return Mono.error(new BadCredentialsException("there is no client-id association with this user-id"));
            }
        }
    }

    private Mono<UsernamePasswordAuthenticationToken> checkClientInOrganization(Authentication authentication, UUID userId, UUID clientId) {
        LOG.info("checking client exists in clientOrganization");

        Optional<ClientOrganization> optionalClientOrganization = clientOrganizationRepository.findByClientId(clientId);
        optionalClientOrganization.ifPresent(clientOrganization -> LOG.info("clientOrganization exists with clientId: {}", clientId));

        if (optionalClientOrganization.isEmpty()) {
            LOG.error("client-id {} not found in clientOrganization", clientId);
            return Mono.empty(); // return empty if there is no client organization association for this client-id
           //return Mono.error(new BadCredentialsException("no clientId " + clientId + " found in ClientOrganization"));
        }

        ClientOrganization clientOrganization = optionalClientOrganization.get();

        // client-id is associated to organization-id, check user-id is also in organization-id
        return userExistInOrganization(userId, clientOrganization.getOrganizationId())
                .filter(aBoolean -> aBoolean)
                .switchIfEmpty(Mono.error(new BadCredentialsException("user does not exists in organization")))
                .flatMap(aBoolean -> getAuth(authentication, clientId));//.block();
    }

    private Mono<UsernamePasswordAuthenticationToken> getAuth(Authentication authentication, UUID clientId) {
        String password = authentication.getCredentials().toString();

        LOG.info("make authentication call out to endpoint: {}", authenticateEndpoint);

        WebClient.ResponseSpec responseSpec = webClientBuilder.build().post().uri(authenticateEndpoint).bodyValue(
                        Map.of("authenticationId", authentication.getPrincipal().toString(),
                                "password", password,
                                "clientId", clientId))
                .retrieve();

        //throws exception on authentication not found return with 401 http status
        return responseSpec.bodyToMono(Map.class).map(map -> {
            LOG.info("authentication response contains: {}", map);

            final List<GrantedAuthority> grantedAuths = new ArrayList<>();

            if (map.get(ROLES) != null) {
               String roleList = map.get(ROLES).toString();
               roleList = roleList.replace("[", "");
               roleList = roleList.replace("]", "");

               LOG.debug("go thru each roleName from list and add to grantedAuths: {}", roleList);
               String[] roles = roleList.split(",");
               for(String role: roles) {
                   LOG.info("add role: {}", role);
                   if (!role.trim().isEmpty()) {
                       grantedAuths.add(new SimpleGrantedAuthority(role));
                   }
               }
            }

            UUID userId = UUID.fromString(map.get("userId").toString());
            //final UserDetails principal = new User(userId.toString(), password, grantedAuths);
            final UserId principal = new UserId(userId.toString(), authentication.getPrincipal().toString(), password, grantedAuths);

            //final UserDetails principal = new UserId(userId, authentication.getPrincipal().toString(), password, grantedAuths);

            if(grantedAuths.isEmpty()) {
                LOG.info("roles is empty, add a default one for now.");
                grantedAuths.add(new SimpleGrantedAuthority("USER_ROLE"));
            }

            LOG.info("storing userId as principal");
            LOG.info("returning using custom authenticator with grantedAuths added: {}", grantedAuths);
            return new UsernamePasswordAuthenticationToken(principal, password, grantedAuths);

        }).onErrorResume(throwable -> {
            LOG.error("error on authentication-rest-service to endpoint '{}' with error: {}", authenticateEndpoint,
                    throwable.getMessage());
            LOG.debug("exception", throwable);

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

    /**
     * this is used by the {#AuthenticateRestController}
     * @param authentication
     * @return
     */
    public UsernamePasswordAuthenticationToken restAuth(Authentication authentication, String clientId) {
        String password = authentication.getCredentials().toString();

        LOG.info("make authentication call out to endpoint: {}", authenticateEndpoint);
        LOG.info("clientId: {}", clientId);

        WebClient.ResponseSpec responseSpec = webClientBuilder.build().post().uri(authenticateEndpoint).bodyValue(
                        Map.of("authenticationId", authentication.getPrincipal().toString(),
                                "password", password,
                "clientId", clientId))
                .retrieve();

        //throws exception on authentication not found return with 401 http status
        return responseSpec.bodyToMono(Map.class).map(map -> {
            LOG.info("authentication response contains: {}", map);

            final List<GrantedAuthority> grantedAuths = new ArrayList<>();

            LOG.info("map.get('roles'): {}", map.get(ROLES));

            if (map.get(ROLES) != null) {
                String roleList = map.get(ROLES).toString();
                roleList = roleList.replace("[", "");
                roleList = roleList.replace("]", "");

                LOG.info("go thru each ROLES from list and add to grantedAuths: {}", roleList);
                String[] roles = roleList.split(",");
                for(String role: roles) {
                    LOG.info("add role: {}", role);
                    if (!role.trim().isEmpty()) {
                        grantedAuths.add(new SimpleGrantedAuthority(role));
                    }
                    else {
                        LOG.info("role string is empty: '{}'", role);
                    }
                }
            }
            //final UserDetails principal = new User(authentication.getName(), password, grantedAuths);
            UUID userId = UUID.fromString(map.get("userId").toString());
            LOG.info("username: {}", authentication.getName());

            final UserId principal = new UserId(userId.toString(), authentication.getPrincipal().toString(), password, grantedAuths);

            LOG.info("returning using custom authenticator with grantedAuths added: {}", grantedAuths);

            LOG.info("storing userId as principal in authToken");
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
        }).block();
    }


    private Mono<UUID> getUserId(String authenticationId) {
        StringBuilder userByAuthId = new StringBuilder(userEndpoint.replace("{authenticationId}",
                authenticationId));

        LOG.info("make user call out to endpoint: {}", userByAuthId);

            WebClient.ResponseSpec responseSpec = webClientBuilder.build().get().uri(userByAuthId.toString())
                .retrieve();

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
                    return Mono.error(new BadCredentialsException("Failed to get user by authId"));
                } else {
                    return Mono.error(new BadCredentialsException("Failed to get user by authId"));
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
                LOG.info("return false");
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

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}