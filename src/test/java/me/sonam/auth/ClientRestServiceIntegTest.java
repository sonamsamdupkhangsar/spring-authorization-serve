package me.sonam.auth;

import me.sonam.auth.service.JpaRegisteredClientRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.util.Base64;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * this is for testing 'clients' endpoint
 */
@EnableAutoConfiguration
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes= DefaultAuthorizationServerApplication.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(MockitoExtension.class)
public class ClientRestServiceIntegTest {
    private static final Logger LOG = LoggerFactory.getLogger(ClientRestServiceIntegTest.class);

    @Autowired
    private WebTestClient webTestClient;

    @Autowired
    private JpaRegisteredClientRepository jpaRegisteredClientRepository;

    private String clientId = "messaging-client";

    private String clientSecret = "secret";
    private String base64ClientSecret = Base64.getEncoder().encodeToString(new StringBuilder(clientId)
            .append(":").append(clientSecret).toString().getBytes());

    @Test
    public void create() {
        LOG.info("create registration client");

        saveClient();

        RegisteredClient registeredClient = jpaRegisteredClientRepository.findByClientId("myclient");
        assertThat(registeredClient.getClientSecret()).isEqualTo("{noop}secret");
        LOG.info("clientAuthMethods: {}", registeredClient.getClientAuthenticationMethods());
        assertThat(registeredClient.getClientAuthenticationMethods().size()).isEqualTo(2);

        Set<ClientAuthenticationMethod> authMethods = Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                ClientAuthenticationMethod.CLIENT_SECRET_JWT);

        assertThat(registeredClient.getClientAuthenticationMethods()).contains(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        assertThat(registeredClient.getClientAuthenticationMethods()).contains(ClientAuthenticationMethod.CLIENT_SECRET_JWT);
        for (AuthorizationGrantType au : registeredClient.getAuthorizationGrantTypes()) {
            LOG.info("au: {}", au.getValue());
        }

        assertThat(registeredClient.getAuthorizationGrantTypes()).contains(AuthorizationGrantType.AUTHORIZATION_CODE);
        assertThat(registeredClient.getAuthorizationGrantTypes()).contains(AuthorizationGrantType.REFRESH_TOKEN);
        assertThat(registeredClient.getAuthorizationGrantTypes()).contains(AuthorizationGrantType.CLIENT_CREDENTIALS);
        registeredClient.getScopes().forEach(s -> LOG.info("scopes: {}", s));

        assertThat(registeredClient.getScopes()).contains("openid");
        assertThat(registeredClient.getScopes()).contains("profile");
        assertThat(registeredClient.getScopes()).contains("message.read");
        assertThat(registeredClient.getScopes()).contains("message.write");
        assertThat(registeredClient.getClientSettings().getSetting("settings.client.require-proof-key").toString()).isEqualTo("false");
        assertThat(registeredClient.getClientSettings().getSetting("settings.client.require-authorization-consent").toString()).isEqualTo("true");

        final String encodedSecret  = Base64.getEncoder().encodeToString("myclient:secret".getBytes());
        LOG.info("get access token from new client registration");

        EntityExchangeResult<Map> entityExchangeResult = webTestClient.post().uri("/oauth2/token?grant_type=client_credentials&scope=message.read message.write")
                .headers(httpHeaders -> httpHeaders.setBasicAuth(encodedSecret))
                .exchange().expectStatus().isOk().expectBody(Map.class)
                .returnResult();
        final Map<String, String> map2  = entityExchangeResult.getResponseBody();
        assertThat(map2.get("access_token")).isNotNull();
        LOG.info("access_token: {}", map2.get("access_token"));


        LOG.info("delete clientId");
        webTestClient.delete().uri("/clients/myclient").headers(httpHeaders -> httpHeaders.setBearerAuth(map2.get("access_token")))
                .exchange().expectStatus().isNoContent();
    }

    private void saveClient() {
        var requestBody = Map.of("clientId", "myclient", "clientSecret", "{noop}secret",
                "clientName", "Blog Application",
                "clientAuthenticationMethods", "client_secret_basic,client_secret_jwt",
                "authorizationGrantTypes", "authorization_code,refresh_token,client_credentials",
                "redirectUris", "http://127.0.0.1:8080/login/oauth2/code/my-client-oidc,http://127.0.0.1:8080/authorized",
                "scopes", "openid,profile,message.read,message.write",
                "clientSettings", Map.of("settings.client.require-proof-key", "false", "settings.client.require-authorization-consent", "true"));


        EntityExchangeResult<Map> entityExchangeResult = webTestClient.post()
                .uri("/oauth2/token?grant_type=client_credentials&scope=message.read message.write")
                .headers(httpHeaders -> httpHeaders.setBasicAuth(base64ClientSecret))
                .exchange().expectStatus().isOk().expectBody(Map.class)
                .returnResult();
        final Map<String, String> map = entityExchangeResult.getResponseBody();
        assertThat(map.get("access_token")).isNotNull();

        WebTestClient.ResponseSpec responseSpec = webTestClient.post().uri("/clients").bodyValue(requestBody)
                .headers(httpHeaders -> httpHeaders.setBearerAuth(map.get("access_token")))
                .exchange().expectStatus().isCreated();
        assertThat(responseSpec.expectBody(String.class).returnResult().getResponseBody()).isNotEmpty();
    }


    @Test
    public void update() {
        LOG.info("update registration client by using access_token from this client itself for client credential flow");

        saveClient();
        final String encodedSecret  = Base64.getEncoder().encodeToString("myclient:secret".getBytes());
        LOG.info("get access token from new client registration");

        EntityExchangeResult<Map> entityExchangeResult = webTestClient.post().uri("/oauth2/token?grant_type=client_credentials&scope=message.read message.write")
                .headers(httpHeaders -> httpHeaders.setBasicAuth(encodedSecret))
                .exchange().expectStatus().isOk().expectBody(Map.class)
                .returnResult();
        final Map<String, String> map  = entityExchangeResult.getResponseBody();
        assertThat(map.get("access_token")).isNotNull();
        LOG.info("access_token: {}", map.get("access_token"));
        final String accessToken = map.get("access_token");

        var requestBody = Map.of("clientId", "myclient", "clientSecret", "{noop}secret",
                "clientName", "small blog app",
                "clientAuthenticationMethods", "client_secret_basic,client_secret_jwt",
                "authorizationGrantTypes", "authorization_code,refresh_token,client_credentials",
                "redirectUris", "http://127.0.0.1:8080/login/oauth2/code/my-client-oidc,http://127.0.0.1:8080/authorized",
                "scopes", "openid,profile,message.read,message.write",
                "clientSettings", Map.of("settings.client.require-proof-key", "false", "settings.client.require-authorization-consent", "true"));


        WebTestClient.ResponseSpec responseSpec = webTestClient.put().uri("/clients").bodyValue(requestBody)
                .headers(httpHeaders -> httpHeaders.setBearerAuth(accessToken))
                .exchange().expectStatus().isOk();

        LOG.info("get by clientId and validate name change was updated");
        WebTestClient.ResponseSpec clientResponse = webTestClient.get().uri("/clients/myclient")
                .headers(httpHeaders -> httpHeaders.setBearerAuth(accessToken))
                .exchange().expectStatus().isOk();

        assertThat(clientResponse.expectBody(Map.class).returnResult().getResponseBody().get("clientName")).isEqualTo("small blog app");
    }

}
