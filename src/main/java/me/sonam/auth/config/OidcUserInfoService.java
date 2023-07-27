package me.sonam.auth.config;

import jakarta.ws.rs.BadRequestException;
import me.sonam.auth.service.ClientIdUtil;
import me.sonam.auth.util.JwtPath;
import org.bouncycastle.cert.ocsp.Req;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

/**
 * This will perform a user info lookup by calling user-rest-service with authenticationId {@code id_token}.
 */
@Service
public class OidcUserInfoService {
    private static final Logger LOG = LoggerFactory.getLogger(OidcUserInfoService.class);

    private final UserInfoRepository userInfoRepository = new UserInfoRepository();

    @Value("${auth-server.root}${auth-server.oauth2token.path}${auth-server.oauth2token.params:}")
    private String oauth2TokenEndpoint;
    @Value("${auth-server.oauth2token.path}")
    private String accessTokenPath;

    @Value("${user-rest-service.root}${user-rest-service.userByAuthid}")
    private String userByAuthIdEp;

    @Autowired
    private JwtPath jwtPath;

    private WebClient.Builder webClientBuilder;

    private RequestCache requestCache;

    public OidcUserInfoService(WebClient.Builder webClientBuilder, RequestCache requestCache) {
        this.webClientBuilder = webClientBuilder;
        this.requestCache = requestCache;
    }

    public OidcUserInfo loadUser(String username) {
        LOG.info("loadUser by username: {}", username);

        OidcUserInfo oidcUserInfo = getOidcUserInfoMap(username).flatMap(map ->
                Mono.just(new OidcUserInfo(map))).block();

        LOG.info("oidcUserInfo.claims: {}, oidcUserInfo: {}", oidcUserInfo.getClaims(), oidcUserInfo);
        return oidcUserInfo;
    }

    static class UserInfoRepository {

        private final Map<String, Map<String, Object>> userInfo = new HashMap<>();

        public UserInfoRepository() {
        }

        public Map<String, Object> findByUsername(String username) {
            return this.userInfo.get(username);
        }
    }


    private Mono<Map<String, Object>> getOidcUserInfoMap(String authenticationId) {
        final String userInfoEndpoint = userByAuthIdEp.replace("{authenticationId}", authenticationId);
        LOG.info("making a call to user endpoint: {}", userInfoEndpoint);

        final String requestAccessToken = ClientIdUtil.getRequestAccessToken(requestCache);
        LOG.info("request accesstoken is {}", requestAccessToken);

        if (!jwtPath.getJwtRequest().isEmpty()) {
            JwtPath.JwtRequest.AccessToken accessToken = jwtPath.getJwtRequest().get(0).getAccessToken();
            Mono<String> accessTokenMono = getAccessToken(accessToken);

            return accessTokenMono.flatMap(stringAccessToken -> {
                LOG.info("using client credential access token: {}", stringAccessToken);
                WebClient.ResponseSpec responseSpec = webClientBuilder.build().get().uri(userInfoEndpoint)
                        .headers(httpHeaders -> httpHeaders.setBearerAuth(stringAccessToken))
                        .retrieve();

                return responseSpec.bodyToMono(Map.class).flatMap(map -> {
                            LOG.info("got userInfo from user-rest-service: {}", map);
                            Map<String, Object> oidcUserInfoMap = buildOidcUserInfo(authenticationId, map);
                            return Mono.just(oidcUserInfoMap);

                        })
                        .onErrorResume(throwable -> {
                            LOG.error("error on getting user info from user-rest-service endpoint '{}' with error: {}", userInfoEndpoint,
                                    throwable.getMessage());
                            return Mono.error(new RuntimeException("user info call failed, error: " + throwable.getMessage()));

                    /*if (throwable instanceof WebClientResponseException) {
                        WebClientResponseException webClientResponseException = (WebClientResponseException) throwable;
                        LOG.error("user info call error is: {}", webClientResponseException.getResponseBodyAsString());

                        return Mono.error(new RuntimeException("user info call failed, error: "+
                                webClientResponseException.getResponseBodyAsString()));
                    }
                    else {
                        return Mono.error(new RuntimeException("user info call failed, error: "+ throwable.getMessage()));
                    }*/
                        });
            });
        }
        else {
            return Mono.just(buildOidcUserInfo(authenticationId, new HashMap<>()));
        }
    }

    private static Map<String, Object> buildOidcUserInfo(String authenticationId, Map<String, String> map) {
        return OidcUserInfo.builder()
                .subject(authenticationId)
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
                .zoneinfo(map.get("timeZone"))//"Europe/Paris")
                .locale(map.get("locale"))//"en-US")
                .phoneNumber(map.get("phoneNumber"))//"+1 (604) 555-1234;ext=5678")
                .phoneNumberVerified(Boolean.parseBoolean(map.get("phoneNumberVerified")))
                .claim("address", map.get("address"))//Collections.singletonMap("formatted", "Champ de Mars\n5 Av. Anatole France\n75007 Paris\nFrance"))
                .updatedAt(map.get("updatedAt"))//""1970-01-01T00:00:00Z")
                .build()
                .getClaims();
    }

    private Mono<String> getAccessToken(JwtPath.JwtRequest.AccessToken accessToken) {
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

