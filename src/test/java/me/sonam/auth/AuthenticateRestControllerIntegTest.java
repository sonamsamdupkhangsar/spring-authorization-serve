package me.sonam.auth;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.assertj.core.api.Assertions.anyOf;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;

@EnableAutoConfiguration
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
public class AuthenticateRestControllerIntegTest {
    private static final Logger LOG = LoggerFactory.getLogger(AuthenticateRestControllerIntegTest.class);
    @Autowired
    private WebTestClient webTestClient;

    //@MockBean
    private AuthenticationProvider authenticationProvider;
    private final String messageClient = "messaging-client";

    private final String clientSecret = "secret";
    private final String base64ClientSecret = Base64.getEncoder().encodeToString(new StringBuilder(messageClient)
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

        r.add("authentication-rest-service.root", () ->"http://localhost:"+mockWebServer.getPort());
    }
    /**
     * this method just validates the endpoint can be reached
     * @throws Exception
     */
    @Test
    public void authenticate() throws Exception {
        LOG.info("call authenticate rest endpoint");

        LOG.info("request oauth access token first");
        EntityExchangeResult<Map> tokenEntityExchangeResult = webTestClient.post()
                .uri("/oauth2/token?grant_type=client_credentials&scope=message.read message.write")
                .headers(httpHeaders -> httpHeaders.setBasicAuth(base64ClientSecret))
                .exchange().expectStatus().isOk().expectBody(Map.class)
                .returnResult();


        final Map<String, String> map = tokenEntityExchangeResult.getResponseBody();
        assertThat(map.get("access_token")).isNotNull();
        LOG.info("access_token: {}", map.get("access_token"));


        final List<GrantedAuthority> grantedAuths = new ArrayList<>();
        Map<String, String> roleMaps = new HashMap<>();
        roleMaps.put("roles", "[USER, CLIENT,ADMIN]");

        String roleList = roleMaps.get("roles");
        roleList = roleList.replace("[", "");
        roleList = roleList.replace("]", "");

        LOG.debug("go thru each roleName from list and add to grantedAuths: {}", roleList);
        String[] roles = roleList.split(",");
        for(String role: roles) {
            LOG.info("add role: {}", role);
            grantedAuths.add(new SimpleGrantedAuthority(role));
        }

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new
                UsernamePasswordAuthenticationToken("sonam", "password", grantedAuths);

        final String jsonResponse = "{\"userId\":\"1f442dab-96a3-459e-8605-7f5cd5f82e25\", " +
                "\"roles\":\"[USER, CLIENT, ADMIN]\", \"message\":\"Authentication successful\"}";

        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
                .setResponseCode(200).setBody(jsonResponse));


        //Mockito.when(authenticationProvider.authenticate(any())).thenReturn(usernamePasswordAuthenticationToken);
        LOG.info("make the authenticate request");
        EntityExchangeResult<String> entityExchangeResult = webTestClient.put()
                .uri("/myauthenticate")
                .bodyValue(Map.of("username", "sonam", "password", "hello"))
                .headers(httpHeaders -> httpHeaders.setBearerAuth(map.get("access_token")))
                .exchange().expectStatus().isOk().expectBody(String.class)
                .returnResult();

        RecordedRequest recordedRequest = mockWebServer.takeRequest();
        assertThat(recordedRequest.getMethod()).isEqualTo("POST");
        assertThat(recordedRequest.getPath()).startsWith("/authentications/authenticate");

        LOG.info("response for authenticate is {}", entityExchangeResult.getResponseBody());
    }
}