package me.sonam.auth.service;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

/**
 * This will perform a user info lookup by calling user-rest-service with authenticationId {@code id_token}.
 */
@Service
public class OidcUserInfoService {
    private static final Logger LOG = LoggerFactory.getLogger(OidcUserInfoService.class);
    @Value("${user-rest-service.root}${user-rest-service.userByAuthId}")
    private String userByAuthIdEp;

    @Value("${user-rest-service.root}${user-rest-service.userId}")
    private String userIdEndpoint;

    private WebClient.Builder webClientBuilder;

    public OidcUserInfoService(WebClient.Builder webClientBuilder) {
        this.webClientBuilder = webClientBuilder;
    }

    public OidcUserInfo loadUser(String username) {
        LOG.info("loadUser by username: {}", username);

        OidcUserInfo oidcUserInfo = getOidcUserInfoMap(username).flatMap(map ->
                Mono.just(new OidcUserInfo(map))).block();

        LOG.info("oidcUserInfo.claims: {}, oidcUserInfo: {}", oidcUserInfo.getClaims(), oidcUserInfo);
        return oidcUserInfo;
    }

    private Mono<Map<String, Object>> getOidcUserInfoMap(String authenticationId) {
        final String userInfoEndpoint = userByAuthIdEp.replace("{authenticationId}", authenticationId);
        LOG.info("making a call to user endpoint: {}", userInfoEndpoint);

        WebClient.ResponseSpec responseSpec = webClientBuilder.build().get().uri(userInfoEndpoint)
                        .retrieve();

        return responseSpec.bodyToMono(Map.class).flatMap(map -> {
            LOG.info("got userInfo from user-rest-service: {}", map);
            Map<String, Object> oidcUserInfoMap = buildOidcUserInfo(authenticationId, map);
            return Mono.just(oidcUserInfoMap);
        }).onErrorResume(throwable -> {
            LOG.error("error on getting user info from user-rest-service endpoint '{}' with error: {}",
                    userInfoEndpoint, throwable.getMessage());
            return Mono.error(new RuntimeException("user info call failed, error: " + throwable.getMessage()));
        });
    }

    private static Map<String, Object> buildOidcUserInfo(String authenticationId, Map<String, String> map) {
         OidcUserInfo.Builder builder = OidcUserInfo.builder();

         builder.subject(authenticationId)
                 .name(map.get("firstName"))
                .givenName(map.get("firstName"))
                .familyName(map.get("lastName"))
                .middleName(map.get("middleName"))
                .nickname(map.get("nickname"))
                .preferredUsername(authenticationId)
                .profile(map.get("profile"))
                .picture(map.get("profilePhoto"))
                .website(map.get("website"))
                .email(map.get("email"))
                .emailVerified(Boolean.parseBoolean(map.get("emailVerified")))
                .gender(map.get("gender"))
                .birthdate(map.get("dateOfBirth"))
                .zoneinfo(map.get("timeZone"))
                .locale(map.get("locale"))
                .phoneNumber(map.get("phoneNumber"))
                .phoneNumberVerified(Boolean.parseBoolean(map.get("phoneNumberVerified")))
                .claim("address", map.get("address"))
                .updatedAt(map.get("updatedAt"))
                .build();

         return builder.build().getClaims();
    }
}

