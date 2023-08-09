package me.sonam.auth;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import me.sonam.auth.service.JpaRegisteredClientRepository;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.Resource;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * this is for testing 'clients' endpoint
 */
@EnableAutoConfiguration
@ExtendWith(SpringExtension.class)
@SpringBootTest( webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
public class ClientRestServiceIntegTest {
    private static final Logger LOG = LoggerFactory.getLogger(ClientRestServiceIntegTest.class);
    @Value("classpath:client-credential-access-token.json")
    private Resource refreshTokenResource;
    @Autowired
    private WebTestClient webTestClient;

    @Autowired
    private JpaRegisteredClientRepository jpaRegisteredClientRepository;

    UUID clientId = UUID.randomUUID();
    private String messageClient = "messaging-client";

    private String clientSecret = "secret";
    private String base64ClientSecret = Base64.getEncoder().encodeToString(new StringBuilder(messageClient)
            .append(":").append(clientSecret).toString().getBytes());

    private static MockWebServer mockWebServer;

    @BeforeAll
    static void setupMockWebServer() throws IOException {
        mockWebServer = new MockWebServer();
        mockWebServer.start();

        LOG.info("host: {}, port: {}", mockWebServer.getHostName(), mockWebServer.getPort());
    }

    @AfterAll
    public static void shutdownMockWebServer() throws IOException {
        LOG.info("shutdown and close mockWebServer");
        mockWebServer.shutdown();
        mockWebServer.close();
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) throws IOException {
        r.add("auth-server.root", () -> "http://localhost:"+mockWebServer.getPort());
        r.add("oauth2-token-mediator.root", () -> "http://localhost:"+mockWebServer.getPort());
    }

    @Test
    public void create() throws Exception {
        LOG.info("create registration client");

        saveClient();

        RegisteredClient registeredClient = jpaRegisteredClientRepository.findByClientId(clientId.toString());
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

        final String encodedSecret  = Base64.getEncoder().encodeToString((clientId.toString()+":secret").getBytes());
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

    private void saveClient() throws  Exception {
        LOG.info("request oauth access token first");
        EntityExchangeResult<Map> entityExchangeResult = webTestClient.post()
                .uri("/oauth2/token?grant_type=client_credentials&scope=message.read message.write")
                .headers(httpHeaders -> httpHeaders.setBasicAuth(base64ClientSecret))
                .exchange().expectStatus().isOk().expectBody(Map.class)
                .returnResult();


        final Map<String, String> map = entityExchangeResult.getResponseBody();
        assertThat(map.get("access_token")).isNotNull();

        LOG.info("now make a request to create a client");
        var requestBody = Map.of("clientId", clientId, "clientSecret", "{noop}secret",
                "clientName", "Blog Application",
                "clientAuthenticationMethods", "client_secret_basic,client_secret_jwt",
                "authorizationGrantTypes", "authorization_code,refresh_token,client_credentials",
                "redirectUris", "http://127.0.0.1:8080/login/oauth2/code/my-client-oidc,http://127.0.0.1:8080/authorized",
                "scopes", "openid,profile,message.read,message.write",
                "clientSettings", Map.of("settings.client.require-proof-key", "false", "settings.client.require-authorization-consent", "true"),
                "mediateToken", "true");

        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
                .setResponseCode(200).setBody(refreshTokenResource.getContentAsString(StandardCharsets.UTF_8)));


        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
                .setResponseCode(200).setBody("{\"message\": \"saved client, count of client by clientId: 1\"}"));

        WebTestClient.ResponseSpec responseSpec = webTestClient.post().uri("/clients").bodyValue(requestBody)
                .headers(httpHeaders -> httpHeaders.setBearerAuth(map.get("access_token")))
                .exchange().expectStatus().isCreated();
        assertThat(responseSpec.expectBody(String.class).returnResult().getResponseBody()).isNotEmpty();

        // take request for mocked response of access token
        RecordedRequest recordedRequest = mockWebServer.takeRequest();
        assertThat(recordedRequest.getMethod()).isEqualTo("POST");
        assertThat(recordedRequest.getPath()).startsWith("/oauth2/token?grant_type=client_credentials");

        LOG.info("take request for mocked response to token-mediator for client save");
        recordedRequest = mockWebServer.takeRequest();
        assertThat(recordedRequest.getMethod()).isEqualTo("PUT");
        assertThat(recordedRequest.getPath()).startsWith("/oauth2-token-mediator/clients");
    }


    @Test
    public void update() throws Exception {
        LOG.info("update registration client by using access_token from this client itself for client credential flow");

        saveClient();
        final String encodedSecret  = Base64.getEncoder().encodeToString((clientId.toString()+":secret").getBytes());
        LOG.info("get access token from new client registration");

        EntityExchangeResult<Map> entityExchangeResult = webTestClient.post().uri("/oauth2/token?grant_type=client_credentials&scope=message.read message.write")
                .headers(httpHeaders -> httpHeaders.setBasicAuth(encodedSecret))
                .exchange().expectStatus().isOk().expectBody(Map.class)
                .returnResult();
        final Map<String, String> map  = entityExchangeResult.getResponseBody();
        assertThat(map.get("access_token")).isNotNull();
        LOG.info("access_token: {}", map.get("access_token"));
        final String accessToken = map.get("access_token");

        var requestBody = Map.of("clientId", clientId, "clientSecret", "{noop}secret",
                "clientName", "small blog app",
                "clientAuthenticationMethods", "client_secret_basic,client_secret_jwt",
                "authorizationGrantTypes", "authorization_code,refresh_token,client_credentials",
                "redirectUris", "http://127.0.0.1:8080/login/oauth2/code/my-client-oidc,http://127.0.0.1:8080/authorized",
                "scopes", "openid,profile,message.read,message.write",
                "clientSettings", Map.of("settings.client.require-proof-key", "false", "settings.client.require-authorization-consent", "true"));

        convertMapToJson(requestBody);
        LOG.info("update clent");

        LOG.info("send a mock accesstoken for making a call to toke-mediator delete call");
        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
                .setResponseCode(200).setBody(refreshTokenResource.getContentAsString(StandardCharsets.UTF_8)));

        LOG.info("mock the delete call from token-mediator call");
        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
                .setResponseCode(200).setBody("{\"message\": \"deleted clientId: "+clientId+"\"}"));

        WebTestClient.ResponseSpec responseSpec = webTestClient.put().uri("/clients").bodyValue(requestBody)
                .headers(httpHeaders -> httpHeaders.setBearerAuth(accessToken))
                .exchange().expectStatus().isOk();

        // take request for mocked response of access token
        RecordedRequest recordedRequest = mockWebServer.takeRequest();
        assertThat(recordedRequest.getMethod()).isEqualTo("POST");
        assertThat(recordedRequest.getPath()).startsWith("/oauth2/token?grant_type=client_credentials");

        LOG.info("take request for mocked response to token-mediator for client delete");
        recordedRequest = mockWebServer.takeRequest();
        assertThat(recordedRequest.getMethod()).isEqualTo("DELETE");
        assertThat(recordedRequest.getPath()).startsWith("/oauth2-token-mediator/clients");

        LOG.info("get by clientId and validate name change was updated");
        WebTestClient.ResponseSpec clientResponse = webTestClient.get().uri("/clients/"+clientId)
                .headers(httpHeaders -> httpHeaders.setBearerAuth(accessToken))
                .exchange().expectStatus().isOk();

        assertThat(clientResponse.expectBody(Map.class).returnResult().getResponseBody().get("clientName")).isEqualTo("small blog app");

        LOG.info("verify /clients/myclient path requires a accesstoken or jwt");
        clientResponse = webTestClient.get().uri("/clients/myclient")
                .exchange().expectStatus().isUnauthorized();
    }

    public void convertMapToJson(Map<String, Object> map) {
        ObjectMapper objectMapper = new ObjectMapper();

        try {
            String json = objectMapper.writeValueAsString(map);
            LOG.info("json: {}", json);
        } catch (JsonProcessingException e) {
            LOG.error("failed to parse map to json", e);
        }
    }
}
