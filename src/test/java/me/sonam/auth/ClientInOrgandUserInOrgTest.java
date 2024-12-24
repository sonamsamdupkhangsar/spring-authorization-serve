package me.sonam.auth;

import org.htmlunit.Page;
import org.htmlunit.WebClient;
import org.htmlunit.html.HtmlButton;
import org.htmlunit.html.HtmlInput;
import org.htmlunit.html.HtmlPage;
import me.sonam.auth.jpa.entity.ClientOrganization;
import me.sonam.auth.jpa.entity.ClientOrganizationId;
import me.sonam.auth.jpa.entity.ClientUser;
import me.sonam.auth.jpa.entity.ClientUserId;
import me.sonam.auth.jpa.repo.ClientOrganizationRepository;
import me.sonam.auth.jpa.repo.HClientUserRepository;
import me.sonam.auth.service.JpaRegisteredClientRepository;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.assertj.core.api.AssertionsForClassTypes;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = {DefaultAuthorizationServerApplication.class}, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
public class ClientInOrgandUserInOrgTest {
    private static final Logger LOG = LoggerFactory.getLogger(ClientInOrgandUserInOrgTest.class);

    private static final String REDIRECT_URI = "http://127.0.0.1:{server.port}/login/oauth2/code/messaging-client-oidc";
    //private static String REDIRECT_URI = "http://localhost:{server.port}/login";

    static final String clientsClientId = "messaging-client";
    static final UUID clientId = UUID.randomUUID();// = "messaging-client";
    private static UUID userId = UUID.randomUUID();
    private static UUID organizationId = UUID.randomUUID();
    private static String AUTHORIZATION_REQUEST; //this is set in {@properties method}
    private static MockWebServer mockWebServer;
    private static String serverPort;

    @Autowired
    private JpaRegisteredClientRepository jpaRegisteredClientRepository;

    @Autowired
    private ClientOrganizationRepository clientOrganizationRepository;

    @Autowired
    private HClientUserRepository clientUserRepository;

    private void saveClientOrganization(final UUID clientId, UUID organizationId) {
        RegisteredClient registeredClient = jpaRegisteredClientRepository.findByClientId(clientsClientId);
        assertThat(registeredClient).isNotNull();
        assertThat(registeredClient.getClientId()).isEqualTo(clientsClientId);

        LOG.info("checking exists in repository");
        if (!clientOrganizationRepository.existsByClientIdAndOrganizationId(UUID.fromString(registeredClient.getId()), organizationId).get()) {
            clientOrganizationRepository.save(new ClientOrganization(UUID.fromString(registeredClient.getId()), organizationId));
            LOG.info("saved clientId {} with organizationId {}", registeredClient.getId(), organizationId);
        }
        LOG.info("done saving clientorganization");
    }

    private void saveClientUser(final UUID clientId, UUID userId) {
        RegisteredClient registeredClient = jpaRegisteredClientRepository.findByClientId(clientsClientId);
        assertThat(registeredClient).isNotNull();
        assertThat(registeredClient.getClientId()).isEqualTo(clientsClientId);

        if (!clientUserRepository.existsById(new ClientUserId(UUID.fromString(registeredClient.getId()), userId))) {
            clientUserRepository.save(new ClientUser(UUID.fromString(registeredClient.getId()), userId));
            LOG.info("saved clientUser");
        }
    }

    @BeforeEach
    public void deleteClientFromOrganizaton() {
        LOG.info("delete clientOrganizationId from clientOrganization with clientId {} and organizationId {}",
                clientId, organizationId);
        clientOrganizationRepository.deleteById(new ClientOrganizationId(clientId, organizationId));

        clientOrganizationRepository.findByClientId(clientId).ifPresent(clientOrganization ->
                LOG.info("still found clientOrganization {}", clientOrganization));
    }

    @BeforeEach
    public void deleteClientUser() {
        LOG.info("delete clientUserId from clientUser");
        clientUserRepository.deleteById(new ClientUserId(clientId, userId));
        //clientUserRepository.deleteAll();
    }

    @BeforeAll
    static void setupMockWebServer() throws IOException {
        mockWebServer = new MockWebServer();
        mockWebServer.start();

        LOG.info("host: {}, port: {}", mockWebServer.getHostName(), mockWebServer.getPort());
        ClientInOrgandUserInOrgTest.serverPort = "http://" + mockWebServer.getHostName() + ":" + mockWebServer.getPort();
    }

    @AfterAll
    public static void shutdownMockWebServer() throws IOException {
        LOG.info("shutdown and close mockWebServer");
        mockWebServer.shutdown();
        mockWebServer.close();
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) throws IOException {
        r.add("authentication-rest-service.root", () -> "http://localhost:" + mockWebServer.getPort());
        r.add("organization-rest-service.root", () -> "http://localhost:" + mockWebServer.getPort());
        r.add("user-rest-service.root", () -> "http://localhost:" + mockWebServer.getPort());
        r.add("auth-server.root", () -> "http://localhost:" + mockWebServer.getPort());

        String redirectUri = REDIRECT_URI.replace("{server.port}", "" + mockWebServer.getPort());
        AUTHORIZATION_REQUEST = UriComponentsBuilder
                .fromPath("/oauth2/authorize")
                .queryParam("response_type", "code")
                .queryParam("client_id", clientsClientId)
                .queryParam("scope", "openid")
                .queryParam("state", "some-state")
                .queryParam("redirect_uri", redirectUri)
                .toUriString();


    }

    @Autowired
    private WebClient webClient;

    @BeforeEach
    public void setUp() {
        this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(true);
        this.webClient.getOptions().setRedirectEnabled(true);
        this.webClient.getCookieManager().clearCookies();    // log out
    }

    /**
     * this will send the Authoriation request url with clientid
     * then user will sign n with username and password
     * a mock response will be returned with the user properties such as id, firstname, lastname, etc
     * a mock response will be returned to indicate user exists in organization
     * a mock response will be returned with user roles in the client-id and 'Authentication successful' message
     *
     * @throws IOException
     * @throws InterruptedException
     */
    @Test
    public void checkClientInOrganizationAndUserExistenceAndUserInOrganization() throws IOException, InterruptedException {
        LOG.info("checkClientInOrganizationAndUserExistenceAndUserInOrganization");
        // Log in
        this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
        this.webClient.getOptions().setRedirectEnabled(true);

        saveClientOrganization(clientId, organizationId);    //save client ("messaging-client" with organizationId)

        //WebResponse response = this.webClient.getPage(AUTHORIZATION_REQUEST).getWebResponse();
        //this response is for getting user by authenticationId (loginId)
        final String jwtString = "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJzb25hbSIsImlzcyI6InNvbmFtLmNsb3VkIiwiYXVkIjoic29uYW0uY2xvdWQiLCJqdGkiOiJmMTY2NjM1OS05YTViLTQ3NzMtOWUyNy00OGU0OTFlNDYzNGIifQ.KGFBUjghvcmNGDH0eM17S9pWkoLwbvDaDBGAx2AyB41yZ_8-WewTriR08JdjLskw1dsRYpMh9idxQ4BS6xmOCQ";

        final String jwtTokenMsg = " {\"access_token\":\"" + jwtString + "\"}";
        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
                .setResponseCode(200).setBody(jwtTokenMsg));

        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
                .setResponseCode(200).setBody("{\"id\":\"" + userId + "\", \"firstName\":\"Dommy\"}"));
        //"\"lastName\":'thecat', \"email\":'dommy@cat.email', \"birthDate\":null, \"profilePhoto\":'null', \"genderId\":null, \"newAccount\":false}"));

        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
                .setResponseCode(200).setBody(jwtTokenMsg));

        // This is for checking user exists in Organization based on the ClientOrganization realtionship
        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
                .setResponseCode(200).setBody("{\"message\":true}"));

        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
                .setResponseCode(200).setBody(jwtTokenMsg));

        //then finally send the  mocked authentication response for callout
        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
                .setResponseCode(200).setBody("{\"roleNames\": \"[user, SuperAdmin]\", \"userId\": \""+ userId +"\",\"message\": \"Authentication successful\"}"));

        // user will be found from clientUser relationship
        //mock role names for authentication http callout
        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
                .setResponseCode(200).setBody("{\"roleNames\": \"[user, SuperAdmin]\",  \"userId\": \""+ userId +"\",\"message\": \"Authentication successful\"}"));

        LOG.info("sign-in to the location page");
        signIn(this.webClient.getPage(AUTHORIZATION_REQUEST), "user1", "password");
        RecordedRequest recordedRequest = mockWebServer.takeRequest();

        AssertionsForClassTypes.assertThat(recordedRequest.getPath()).startsWith("/oauth2/token");
        AssertionsForClassTypes.assertThat(recordedRequest.getMethod()).isEqualTo("POST");

        recordedRequest = mockWebServer.takeRequest();

        assertThat(recordedRequest.getMethod()).isEqualTo("GET");
        assertThat(recordedRequest.getPath()).startsWith("/users/");

        recordedRequest = mockWebServer.takeRequest();
        AssertionsForClassTypes.assertThat(recordedRequest.getPath()).startsWith("/oauth2/token");
        AssertionsForClassTypes.assertThat(recordedRequest.getMethod()).isEqualTo("POST");

        recordedRequest = mockWebServer.takeRequest();
        assertThat(recordedRequest.getMethod()).isEqualTo("GET");
        assertThat(recordedRequest.getPath()).startsWith("/organizations/");//userExistsInOrganization http call

        recordedRequest = mockWebServer.takeRequest();
        AssertionsForClassTypes.assertThat(recordedRequest.getPath()).startsWith("/oauth2/token");
        AssertionsForClassTypes.assertThat(recordedRequest.getMethod()).isEqualTo("POST");

        recordedRequest = mockWebServer.takeRequest();
        assertThat(recordedRequest.getMethod()).isEqualTo("POST");
        assertThat(recordedRequest.getPath()).startsWith("/authentications/authenticate");

        recordedRequest = mockWebServer.takeRequest();
        assertThat(recordedRequest.getMethod()).isEqualTo("GET");
        assertThat(recordedRequest.getPath()).startsWith("/login/oauth2/code/messaging-client-oidc?code=");


        LOG.info("recordedRequest: {}", mockWebServer.getRequestCount());
    }

    private static <P extends Page> P signIn(HtmlPage page, String username, String password) throws IOException {
        LOG.info("page: {}, done end", page.toString());
        HtmlInput usernameInput = page.querySelector("input[name=\"username\"]");
        HtmlInput passwordInput = page.querySelector("input[name=\"password\"]");
        HtmlButton signInButton = page.querySelector("button");

        usernameInput.type(username);
        passwordInput.type(password);
        LOG.info("sign in button: {}", signInButton);
        P p = signInButton.click();
        LOG.info("signIn button clicked?: {}", p.getUrl());

        return p;
    }

}
