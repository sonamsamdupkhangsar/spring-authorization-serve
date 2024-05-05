/*
 * Copyright 2020-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package me.sonam.auth;

import com.gargoylesoftware.htmlunit.*;
import com.gargoylesoftware.htmlunit.html.HtmlButton;
import com.gargoylesoftware.htmlunit.html.HtmlInput;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.parser.HTMLParser;
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
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;
import org.thymeleaf.web.IWebRequest;

import java.io.IOException;
import java.net.URL;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;


@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = {DefaultAuthorizationServerApplication.class}, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
public class AuthorizationServerApplicationUserLoginTests {
	private static final Logger LOG = LoggerFactory.getLogger(AuthorizationServerApplicationUserLoginTests.class);

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
		AuthorizationServerApplicationUserLoginTests.serverPort = "http://"+ mockWebServer.getHostName() + ":"+mockWebServer.getPort();
	}

	@AfterAll
	public static void shutdownMockWebServer() throws IOException {
		LOG.info("shutdown and close mockWebServer");
		mockWebServer.shutdown();
		mockWebServer.close();
	}

	@DynamicPropertySource
	static void properties(DynamicPropertyRegistry r) throws IOException {
		r.add("authentication-rest-service.root", () -> "http://localhost:"+mockWebServer.getPort());
		r.add("organization-rest-service.root", () -> "http://localhost:"+mockWebServer.getPort());
		r.add("user-rest-service.root", () -> "http://localhost:"+mockWebServer.getPort());
		r.add("auth-server.root", () -> "http://localhost:"+mockWebServer.getPort());

		String redirectUri = REDIRECT_URI.replace("{server.port}", "" +mockWebServer.getPort());
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
		this.webClient.getCookieManager().clearCookies();	// log out
	}


	@Test
	public void whenNotLoggedInAndRequestingTokenThenRedirectsToLogin() throws IOException {
		LOG.info("test whenNotLoggedInAndRequestingTokenThenRedirectsToLogin()");
		HtmlPage page = this.webClient.getPage(AUTHORIZATION_REQUEST);

		assertLoginPage(page);
	}


	/**
	 * It will return the user information and then fail with
	 * client not being part of organization and then not in userClient relationship either.
	 * It will throw a exception.
	 * @throws IOException
	 * @throws InterruptedException
	 */
	@Test
	public void checkClientInOrganizationAndClientNotFound() throws IOException, InterruptedException {
		//clientOrganizationRepository.deleteAll();
		LOG.info("test the client organization relationship, user existence in organization");
		// Log in
		this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
		//set redirection false so we can login manually with code below
		this.webClient.getOptions().setRedirectEnabled(true);

		final String jwtString= "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJzb25hbSIsImlzcyI6InNvbmFtLmNsb3VkIiwiYXVkIjoic29uYW0uY2xvdWQiLCJqdGkiOiJmMTY2NjM1OS05YTViLTQ3NzMtOWUyNy00OGU0OTFlNDYzNGIifQ.KGFBUjghvcmNGDH0eM17S9pWkoLwbvDaDBGAx2AyB41yZ_8-WewTriR08JdjLskw1dsRYpMh9idxQ4BS6xmOCQ";

		final String jwtTokenMsg = " {\"access_token\":\""+jwtString+"\"}";
		mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
				.setResponseCode(200).setBody(jwtTokenMsg));

		mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
				.setResponseCode(200).setBody("{\"id\":\""+userId+"\", \"firstName\":\"Dommy\"}"));

		Page page = signIn(/*this.webClient.getPage(response
				.getResponseHeaderValue("location"))*/
				this.webClient.getPage(AUTHORIZATION_REQUEST), "user1", "password");
		//HTMLParser htmlParser = HTMLParser

		//LOG.info("textPage: {}", page.getUrl());

		LOG.info("assert we get back the same login page when client not found");
		//in future look for the error message in the htmlPage
		LOG.info("is html page: {}, url: {}, content: {}", page.isHtmlPage(), page.getUrl(), page.getWebResponse().getContentAsString());

		LOG.info("assert we got back the login page when clientId is not found");
		assertThat(page.getUrl().toString()).endsWith("?error");

		RecordedRequest recordedRequest = mockWebServer.takeRequest();
		LOG.info("should be acesstoken path for recordedRequest: {}", recordedRequest.getPath());
		AssertionsForClassTypes.assertThat(recordedRequest.getPath()).startsWith("/oauth2/token");
		AssertionsForClassTypes.assertThat(recordedRequest.getMethod()).isEqualTo("POST");

		recordedRequest = mockWebServer.takeRequest();
		assertThat(recordedRequest.getMethod()).isEqualTo("GET");
		assertThat(recordedRequest.getPath()).startsWith("/users/");
	}

	/**
     * this will check that on user not found no exception is thrown

	 */
	@Test
	public void checkUserNotExist() throws IOException, InterruptedException {
		LOG.info("test the client organization relationship, user existence in organization");
		// Log in
		this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
		this.webClient.getOptions().setRedirectEnabled(true);

		LOG.info("serverPort: {}", AuthorizationServerApplicationUserLoginTests.serverPort);
		final String jwtString= "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJzb25hbSIsImlzcyI6InNvbmFtLmNsb3VkIiwiYXVkIjoic29uYW0uY2xvdWQiLCJqdGkiOiJmMTY2NjM1OS05YTViLTQ3NzMtOWUyNy00OGU0OTFlNDYzNGIifQ.KGFBUjghvcmNGDH0eM17S9pWkoLwbvDaDBGAx2AyB41yZ_8-WewTriR08JdjLskw1dsRYpMh9idxQ4BS6xmOCQ";

		final String jwtTokenMsg = " {\"access_token\":\""+jwtString+"\"}";
		mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
				.setResponseCode(200).setBody(jwtTokenMsg));

		//this response is for getting user by authenticationId (loginId)
		mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
				.setResponseCode(400).setBody("{\"error\":\"user not found\"}"));
/*
		String locationHeader = response.getResponseHeaderValue("location");
		LOG.info("locationHeader: {}", locationHeader);*/

		signIn(this.webClient.getPage(AUTHORIZATION_REQUEST), "user1", "password");

		LOG.info("take request");
		RecordedRequest recordedRequest = mockWebServer.takeRequest();

		LOG.info("should be acesstoken path for recordedRequest: {}", recordedRequest.getPath());
		AssertionsForClassTypes.assertThat(recordedRequest.getPath()).startsWith("/oauth2/token");
		AssertionsForClassTypes.assertThat(recordedRequest.getMethod()).isEqualTo("POST");

		recordedRequest = mockWebServer.takeRequest();

		assertThat(recordedRequest.getMethod()).isEqualTo("GET");
		assertThat(recordedRequest.getPath()).startsWith("/users/");
	}

    /**
	 * this will test when user is not in organization but in ClientUser
	 *
	 * @throws IOException
	 * @throws InterruptedException
	 */

	@Test
	public void checkClientInOrganizationAndClientFoundInClientUser() throws IOException, InterruptedException {
		LOG.info("test the client organization relationship, user existence in organization");
		//clear out userOrganization relationship if there was any from prior relationship

		// Log in
		this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
		this.webClient.getOptions().setRedirectEnabled(true);


		//save User uuid with clientId
		saveClientUser(clientId, userId);
		final String jwtString= "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJzb25hbSIsImlzcyI6InNvbmFtLmNsb3VkIiwiYXVkIjoic29uYW0uY2xvdWQiLCJqdGkiOiJmMTY2NjM1OS05YTViLTQ3NzMtOWUyNy00OGU0OTFlNDYzNGIifQ.KGFBUjghvcmNGDH0eM17S9pWkoLwbvDaDBGAx2AyB41yZ_8-WewTriR08JdjLskw1dsRYpMh9idxQ4BS6xmOCQ";

		final String jwtTokenMsg = " {\"access_token\":\""+jwtString+"\"}";
		mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
				.setResponseCode(200).setBody(jwtTokenMsg));

		//mock response for user-id http callout
		mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
				.setResponseCode(200).setBody("{\"id\":\""+userId+"\", \"firstName\":\"Dommy\"}"));

		mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
				.setResponseCode(200).setBody(jwtTokenMsg));


		// user will be found from clientUser relationship
		//mock role names for authentication http callout
		mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
				.setResponseCode(200).setBody("{\"roleNames\": \"[user, SuperAdmin]\", \"message\": \"Authentication successful\"}"));

		//it seems like we need to mock one more response for the redirection to redirecUris: /login/oauth2/code/messaging-client-oidc?code=...
		mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
				.setResponseCode(200).setBody("{\"roleNames\": \"[user, SuperAdmin]\", \"message\": \"Authentication successful\"}"));


		//WebResponse response = this.webClient.getPage(AUTHORIZATION_REQUEST).getWebResponse();

		LOG.info("sign-in to the location page");

		//login should work for client as client should be found in ClientUser relationship
		signIn(/*this.webClient.getPage(response
				.getResponseHeaderValue("location"))*/this.webClient.getPage(AUTHORIZATION_REQUEST),
				"user1", "password");

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
		assertThat(recordedRequest.getMethod()).isEqualTo("POST");
		assertThat(recordedRequest.getPath()).startsWith("/authentications/authenticate");

		recordedRequest = mockWebServer.takeRequest();
		assertThat(recordedRequest.getMethod()).isEqualTo("GET");
		assertThat(recordedRequest.getPath()).startsWith("/login/oauth2/code/messaging-client-oidc?code=");
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

	private static void assertLoginPage(HtmlPage page) {
		assertThat(page.getUrl().toString()).endsWith("/");

		HtmlInput usernameInput = page.querySelector("input[name=\"username\"]");
		HtmlInput passwordInput = page.querySelector("input[name=\"password\"]");
		HtmlButton signInButton = page.querySelector("button");

		assertThat(usernameInput).isNotNull();
		assertThat(passwordInput).isNotNull();
		assertThat(signInButton.getTextContent()).isEqualTo("Sign in");
	}

}
