package me.sonam.auth;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import me.sonam.auth.jpa.repo.HClientUserRepository;
import me.sonam.auth.rest.util.MyPair;
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
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.setDescriptionConsumer;

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

    @Autowired
    private HClientUserRepository clientUserRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    UUID clientId = UUID.randomUUID();
    //UUID messageClient = UUID.randomUUID();
    //String clientId = "test-private-client";  //this is created in the test
    private String messageClient = "messaging-client";
    private String clientSecret = "secret";
    private String base64ClientSecret = Base64.getEncoder().encodeToString(new StringBuilder(messageClient.toString())
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
        final String accessToken  = getOauth2Token(messageClient, "secret");

        LOG.info("oauth2Token: {}", accessToken);

        UUID userId = UUID.randomUUID();
        saveClient(clientId.toString(),"{noop}"+clientSecret, userId, accessToken);

        RegisteredClient registeredClient = jpaRegisteredClientRepository.findByClientId(messageClient);
        assertThat(registeredClient).isNotNull();

        assertThat(passwordEncoder.matches("secret", registeredClient.getClientSecret())).isTrue();
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

        //secret is encoded but for base64 use {noop}secret

        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
                .setResponseCode(200).setBody("{\"access_token\": \"eyJraWQiOiJlOGQ3MjIzMC1iMDgwLTRhZjEtODFkOC0zMzE3NmNhMTM5ODIiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI3NzI1ZjZmZC1kMzk2LTQwYWYtOTg4Ni1jYTg4YzZlOGZjZDgiLCJhdWQiOiI3NzI1ZjZmZC1kMzk2LTQwYWYtOTg4Ni1jYTg4YzZlOGZjZDgiLCJuYmYiOjE3MTQ3NTY2ODIsImlzcyI6Imh0dHA6Ly9teS1zZXJ2ZXI6OTAwMSIsImV4cCI6MTcxNDc1Njk4MiwiaWF0IjoxNzE0NzU2NjgyLCJqdGkiOiI0NDBlZDY0My00MzdkLTRjOTMtYTZkMi1jNzYxNjFlNDRlZjUifQ.fjqgoczZbbmcnvYpVN4yakpbplp7EkDyxslvar5nXBFa6mgIFcZa29fwIKfcie3oUMQ8MDWxayak5PZ_QIuHwTvKSWHs0WL91ljf-GT1sPi1b4gDKf0rJOwi0ClcoTCRIx9-WGR6t2BBR1Rk6RGF2MW7xKw8M-RMac2A2mPEPJqoh4Pky1KgxhZpEXixegpAdQIvBgc0KBZeQme-ZzTYugB8EPUmGpMlfd-zX_vcR1ijxi8e-LRRJMqmGkc9GXfrH7MOKNQ_nu6pc6Gish2v_iuUEcpPHXrfqzGb9IHCLvfuLSaTDcYKYjQaEUAp-1uDW8-5posjiUV2eBiU48ajYg\", \"token_type\":\"Bearer\", \"expires_in\":\"299\"}"));

        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
                .setResponseCode(200).setBody("{\"message\": \"deleted clientid in token-mediator: "+clientId+"\"}"));

        LOG.info("delete clientId");
        webTestClient.delete().uri("/clients/"+clientId+"/user-id/"+userId)
                .headers(httpHeaders -> httpHeaders.setBearerAuth(accessToken))
                .exchange().expectStatus().isNoContent();

        RecordedRequest recordedRequest = mockWebServer.takeRequest();
        assertThat(recordedRequest.getMethod()).isEqualTo("POST");
        assertThat(recordedRequest.getPath()).startsWith("/oauth2/token");

        recordedRequest = mockWebServer.takeRequest();
        assertThat(recordedRequest.getMethod()).isEqualTo("DELETE");
        assertThat(recordedRequest.getPath()).startsWith("/oauth2-token-mediator/clients");

        assertThat(clientUserRepository.existsByClientId(UUID.fromString(registeredClient.getId()))).isFalse();
    }



    @Test
    public void update() throws Exception {
        LOG.info("update registration client by using access_token from this client itself for client credential flow");
        final String messageClientAccessToken = getOauth2Token(messageClient, clientSecret); //get token using messageClient first

        UUID userId = UUID.randomUUID();
        saveClient(clientId.toString(), "{noop}"+clientSecret, userId, messageClientAccessToken);

        final String clientIdAccessToken = getOauth2Token(clientId.toString(), "{noop}secret");

        LOG.info("send a mock accesstoken for making a call to toke-mediator delete call");
        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
                .setResponseCode(200).setBody(refreshTokenResource.getContentAsString(StandardCharsets.UTF_8)));

        LOG.info("mock the delete call from token-mediator call");
        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
                .setResponseCode(200).setBody("{\"message\": \"deleted clientId: "+clientId+"\"}"));

        RegisteredClient registeredClient = getRegisteredClientFromRestService(clientId.toString(), clientIdAccessToken);
        Map<String, String> rcMap = jpaRegisteredClientRepository.getMap(registeredClient);
        rcMap.put("redirectUris", "http://www.sonam.cloud");
        rcMap.put("userId", userId.toString());
        rcMap.put("mediateToken", "false");


        Map<String, Object> registeredClientMap = updateClient(rcMap, clientIdAccessToken);

        RegisteredClient registeredClient1 = jpaRegisteredClientRepository.build(registeredClientMap);

        // take request for mocked response of access token
        RecordedRequest recordedRequest = mockWebServer.takeRequest();
        assertThat(recordedRequest.getMethod()).isEqualTo("POST");
        assertThat(recordedRequest.getPath()).startsWith("/oauth2/token");

        LOG.info("take request for mocked response to token-mediator for client delete");
        recordedRequest = mockWebServer.takeRequest();
        assertThat(recordedRequest.getMethod()).isEqualTo("DELETE");
        assertThat(recordedRequest.getPath()).startsWith("/oauth2-token-mediator/clients");

        assertThat(registeredClient1.getRedirectUris()).contains("http://www.sonam.cloud");


        Map<String, Object> map2 = getClientById(registeredClient1.getId(), clientIdAccessToken);
        RegisteredClient registeredClient2 = jpaRegisteredClientRepository.build(map2);

        assertThat(registeredClient2.getClientName()).isEqualTo(registeredClient1.getClientName());
        assertThat(registeredClient2.getId()).isEqualTo(registeredClient1.getClientId());

        map2 = getClientByClientId(registeredClient1.getClientId(), clientIdAccessToken);
        registeredClient2 = jpaRegisteredClientRepository.build(map2);

        assertThat(registeredClient2.getClientName()).isEqualTo(registeredClient1.getClientName());
        assertThat(registeredClient2.getId()).isEqualTo(registeredClient1.getClientId());

    }

    /**
     * this will test the "get all client association with user".
     * @throws Exception
     */
    @Test
    public void getAllClientIdAssociatedWithUser() throws Exception {
        LOG.info("get all client ids by user-id");
        final String messageClientAccessToken = getOauth2Token(messageClient, clientSecret); //get token using messageClient first
        LOG.info("messageClientAccessToken: {}", messageClientAccessToken);
        UUID userId = UUID.randomUUID();

        List<MyPair<String, String>> list = getClientIdsAssociatedWithUser(userId, messageClientAccessToken);
        assertThat(list).isNotNull();
        assertThat(list).isEmpty();

        UUID testClient1 = UUID.randomUUID();
        saveClient(testClient1.toString(), "{noop}"+clientSecret, userId, messageClientAccessToken);
        list = getClientIdsAssociatedWithUser(userId, messageClientAccessToken);
        assertThat(list.size()).isEqualTo(1);
        assertThat(list.get(0).getKey()).isNotNull();
        assertThat(list.get(0).getKey()).isEqualTo(testClient1.toString());
        assertThat(list.get(0).getValue()).isEqualTo(testClient1.toString());
        assertThat(list).contains(new MyPair<>(testClient1.toString(), testClient1.toString()));

        UUID testClient2= UUID.randomUUID();
        saveClient(testClient2.toString(), "{noop}"+clientSecret, userId, messageClientAccessToken);
        list = getClientIdsAssociatedWithUser(userId, messageClientAccessToken);
        assertThat(list.size()).isEqualTo(2);
        assertThat(list).contains(new MyPair<>(testClient1.toString(), testClient1.toString()));
        assertThat(list).contains(new MyPair<>(testClient2.toString(), testClient2.toString()));

        UUID testClient3 = UUID.randomUUID();
        saveClient(testClient3.toString(), "{noop}"+clientSecret, userId, messageClientAccessToken);
        list = getClientIdsAssociatedWithUser(userId, messageClientAccessToken);
        assertThat(list.size()).isEqualTo(3);
        assertThat(list.get(2).getKey()).isNotNull();
        assertThat(list).contains(new MyPair<>(testClient1.toString(), testClient1.toString()));
        assertThat(list).contains(new MyPair<>(testClient2.toString(), testClient2.toString()));
        assertThat(list).contains(new MyPair<>(testClient3.toString(), testClient3.toString()));

        UUID testClient4 = UUID.randomUUID();
        saveClient(testClient4.toString(), "{noop}"+clientSecret, userId, messageClientAccessToken);
        list = getClientIdsAssociatedWithUser(userId, messageClientAccessToken);
        assertThat(list.size()).isEqualTo(4);
        assertThat(list.get(3).getKey()).isNotNull();
        assertThat(list).contains(new MyPair<>(testClient1.toString(), testClient1.toString()));
        assertThat(list).contains(new MyPair<>(testClient2.toString(), testClient2.toString()));
        assertThat(list).contains(new MyPair<>(testClient3.toString(), testClient3.toString()));
        assertThat(list).contains(new MyPair<>(testClient4.toString(), testClient4.toString()));

        UUID testClient5 = UUID.randomUUID();
        saveClient(testClient5.toString(), "{noop}"+clientSecret, userId, messageClientAccessToken);
        list = getClientIdsAssociatedWithUser(userId, messageClientAccessToken);
        assertThat(list.size()).isEqualTo(5);
        assertThat(list.get(4).getKey()).isNotNull();
        assertThat(list).contains(new MyPair<>(testClient1.toString(), testClient1.toString()));
        assertThat(list).contains(new MyPair<>(testClient2.toString(), testClient2.toString()));
        assertThat(list).contains(new MyPair<>(testClient3.toString(), testClient3.toString()));
        assertThat(list).contains(new MyPair<>(testClient4.toString(), testClient4.toString()));
        assertThat(list).contains(new MyPair<>(testClient5.toString(), testClient5.toString()));
    }

    private String getOauth2Token(String clientId, String secret) {
        LOG.info("clientId: {}, secret: {}", clientId, secret);
        final String encodedSecret  = Base64.getEncoder().encodeToString((clientId +":"+secret).getBytes());

        MultiValueMap<String, Object> mvm = new LinkedMultiValueMap<>();
        mvm.add("grant_type", "client_credentials");
        mvm.add("scopes", List.of("message.read", "message.write"));

        EntityExchangeResult<Map<String, String>> entityExchangeResult = webTestClient.post().uri("/oauth2/token")
                .headers(httpHeaders -> httpHeaders.setBasicAuth(encodedSecret))
                .bodyValue(mvm)
                .exchange().expectStatus().isOk().expectBody(new ParameterizedTypeReference<Map<String, String>>() {
                })
                .returnResult();
        Map<String, String> tokenMap = entityExchangeResult.getResponseBody();
        assertThat(tokenMap).isNotNull();
        assertThat(tokenMap.get("access_token")).isNotNull();
        return tokenMap.get("access_token");
    }

    private void saveClient(String clientId, String clientSecret, UUID userId, String accessToken) throws  Exception {
        LOG.info("now make a request to create a client");
        RegisteredClient registeredClient = RegisteredClient.withId(clientId.toString())
                .clientId(clientId.toString())
                .clientSecret(clientSecret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
                .redirectUri("http://127.0.0.1:8080/authorized")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("message.read")
                .scope("message.write")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).requireProofKey(false).build())
                .build();

        Map<String, Object> regClientMap = jpaRegisteredClientRepository.getMapObject(registeredClient, false);
        regClientMap.put("userId", userId);
        LOG.info("requestBody: {}", regClientMap);

        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
                .setResponseCode(200).setBody(refreshTokenResource.getContentAsString(StandardCharsets.UTF_8)));

        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
                .setResponseCode(200).setBody("{\"message\": \"saved client, count of client by clientId: 1\"}"));

        Mono<Map> mapMono = webTestClient.post().uri("/clients").bodyValue(regClientMap)
                .headers(httpHeaders -> httpHeaders.setBearerAuth(accessToken))
                .exchange().expectStatus().isCreated().returnResult(Map.class).getResponseBody().single();

        StepVerifier.create(mapMono).assertNext(map1 -> {
            LOG.info("map: {}", map1);
            assertThat(map1.get("id")).isNotNull();
            LOG.info("map1.id: {}", map1.get("id"));
        }).verifyComplete();

        // take request for mocked response of access token
        RecordedRequest recordedRequest = mockWebServer.takeRequest();
        assertThat(recordedRequest.getMethod()).isEqualTo("POST");
        assertThat(recordedRequest.getPath()).startsWith("/oauth2/token");

        LOG.info("take request for mocked response to token-mediator for client when mediateToken field is not present");
        recordedRequest = mockWebServer.takeRequest();
        assertThat(recordedRequest.getMethod()).isEqualTo("DELETE");
        assertThat(recordedRequest.getPath()).startsWith("/oauth2-token-mediator/clients");
    }


    private RegisteredClient getRegisteredClientFromRestService(String clientId, String token) {

        EntityExchangeResult<Map<String, Object>> entityExchangeResult = webTestClient.get()
                .uri("/clients/client-id/"+clientId).headers(httpHeaders ->  httpHeaders.setBearerAuth(token))
                .accept(MediaType.APPLICATION_JSON).exchange().expectBody(new ParameterizedTypeReference<Map<String, Object>>() {}).returnResult();

        assertThat(entityExchangeResult).isNotNull();
        assertThat(entityExchangeResult.getResponseBody()).isNotNull();

        Map<String, Object> map = entityExchangeResult.getResponseBody();
        RegisteredClient registeredClient = jpaRegisteredClientRepository.build(map);
        assertThat(registeredClient).isNotNull();
        return registeredClient;
    }

    private Map<String, Object> updateClient(Map<String, String> map, String token) {

        EntityExchangeResult<Map<String, Object>> entityExchangeResult = webTestClient.put().uri("/clients")
                .bodyValue(map)
                .headers(httpHeaders -> httpHeaders.setBearerAuth(token))
                .exchange().expectStatus().isOk().expectBody(new ParameterizedTypeReference<Map<String, Object>>(){}).returnResult();

        assertThat(entityExchangeResult).isNotNull();
        assertThat(entityExchangeResult.getResponseBody()).isNotNull();

        return entityExchangeResult.getResponseBody();
    }

    private Map<String, Object> getClientById(String id, String accessToken) {
        EntityExchangeResult<Map<String, Object>> entityExchangeResult = webTestClient.get().uri("/clients/"+id)
                .headers(httpHeaders -> httpHeaders.setBearerAuth(accessToken))
                .exchange().expectStatus().isOk().expectBody(new ParameterizedTypeReference<Map<String, Object>>(){}).returnResult();

        assertThat(entityExchangeResult).isNotNull();
        assertThat(entityExchangeResult.getResponseBody()).isNotNull();

        return entityExchangeResult.getResponseBody();
    }

    private Map<String, Object> getClientByClientId(String clientId, String accessToken) {
        EntityExchangeResult<Map<String, Object>> entityExchangeResult = webTestClient.get().uri("/clients/client-id/"+clientId)
                .headers(httpHeaders -> httpHeaders.setBearerAuth(accessToken))
                .exchange().expectStatus().isOk().expectBody(new ParameterizedTypeReference<Map<String, Object>>(){}).returnResult();

        assertThat(entityExchangeResult).isNotNull();
        assertThat(entityExchangeResult.getResponseBody()).isNotNull();

        return entityExchangeResult.getResponseBody();
    }

    private List<MyPair<String, String>> getClientIdsAssociatedWithUser(UUID userId, String accessToken) {
        EntityExchangeResult<List<MyPair<String, String>>> entityExchangeResult = webTestClient.get()
                .uri("/clients/users/"+userId)
                .headers(httpHeaders -> httpHeaders.setBearerAuth(accessToken))
                .exchange().expectStatus().isOk().expectBody(new ParameterizedTypeReference<
                        List<MyPair<String, String>>>(){}).returnResult();

        assertThat(entityExchangeResult).isNotNull();
        assertThat(entityExchangeResult.getResponseBody()).isNotNull();

        return entityExchangeResult.getResponseBody();
    }
}
