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

import com.gargoylesoftware.htmlunit.Page;
import com.gargoylesoftware.htmlunit.TextPage;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebResponse;
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
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
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

	static final String clientId = "messaging-client";
	private static UUID userId = UUID.randomUUID();
	private static UUID organizationId = UUID.randomUUID();
	private static String AUTHORIZATION_REQUEST; //this is set in {@properties method}
	private static MockWebServer mockWebServer;

	@Autowired
	private ClientOrganizationRepository clientOrganizationRepository;

	@Autowired
	private HClientUserRepository clientUserRepository;

	private void saveClientOrganization(final String clientId, UUID organizationId) {
		if (!clientOrganizationRepository.existsByClientId(clientId).get()) {
			clientOrganizationRepository.save(new ClientOrganization(clientId, organizationId));
			LOG.info("saved clientId {} with organizationId {}", clientId, organizationId);
		}
	}
	private void saveClientUser(final String clientId, UUID userId) {
		if (!clientUserRepository.existsById(new ClientUserId(clientId, userId))) {
			clientUserRepository.save(new ClientUser(clientId, userId));
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

	public
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
		r.add("authentication-rest-service.root", () -> "http://localhost:"+mockWebServer.getPort());
		r.add("organization-rest-service.root", () -> "http://localhost:"+mockWebServer.getPort());
		r.add("user-rest-service.root", () -> "http://localhost:"+mockWebServer.getPort());
		r.add("auth-server.root", () -> "http://localhost:"+mockWebServer.getPort());

		String redirectUri = REDIRECT_URI.replace("{server.port}", "" +mockWebServer.getPort());
		AUTHORIZATION_REQUEST = UriComponentsBuilder
				.fromPath("/oauth2/authorize")
				.queryParam("response_type", "code")
				.queryParam("client_id", clientId)
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
	 * this will send the Authoriation request url with clientid
	 * then user will sign n with username and password
	 * a mock response will be returned with the user properties such as id, firstname, lastname, etc
	 * a mock response will be returned to indicate user exists in organization
	 * a mock response will be returned with user roles in the client-id and 'Authentication successful' message
	 * @throws IOException
	 * @throws InterruptedException
	 */
	@Test
	public void checkClientInOrganizationAndUserExistenceAndUserInOrganization() throws IOException, InterruptedException {
		LOG.info("test the client organization relationship, user existence in organization");
		// Log in
		this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
		this.webClient.getOptions().setRedirectEnabled(false);

		saveClientOrganization(clientId, organizationId);	//save client ("messaging-client" with organizationId)

		WebResponse response = this.webClient.getPage(AUTHORIZATION_REQUEST).getWebResponse();
		//this response is for getting user by authenticationId (loginId)
		final String jwtString= "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJzb25hbSIsImlzcyI6InNvbmFtLmNsb3VkIiwiYXVkIjoic29uYW0uY2xvdWQiLCJqdGkiOiJmMTY2NjM1OS05YTViLTQ3NzMtOWUyNy00OGU0OTFlNDYzNGIifQ.KGFBUjghvcmNGDH0eM17S9pWkoLwbvDaDBGAx2AyB41yZ_8-WewTriR08JdjLskw1dsRYpMh9idxQ4BS6xmOCQ";

		final String jwtTokenMsg = " {\"access_token\":\""+jwtString+"\"}";
		mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
				.setResponseCode(200).setBody(jwtTokenMsg));

		mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
				.setResponseCode(200).setBody("{\"id\":\""+userId+"\", \"firstName\":\"Dommy\"}"));
						//"\"lastName\":'thecat', \"email\":'dommy@cat.email', \"birthDate\":null, \"profilePhoto\":'null', \"genderId\":null, \"newAccount\":false}"));

		mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
				.setResponseCode(200).setBody(jwtTokenMsg));
		// This is for checking user exists in Organization based on the ClientOrganization realtionship
		mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
				.setResponseCode(200).setBody("{\"message\":true}"));

		//then finally send the  mocked authentication response for callout
		mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
				.setResponseCode(200).setBody("{\"roleNames\": \"[user, SuperAdmin]\", \"message\": \"Authentication successful\"}"));

		LOG.info("sign-in to the location page");
		signIn(this.webClient.getPage(response.getResponseHeaderValue("location")), "user1", "password");
		RecordedRequest recordedRequest = mockWebServer.takeRequest();

		LOG.info("should be acesstoken path for recordedRequest: {}", recordedRequest.getPath());
		AssertionsForClassTypes.assertThat(recordedRequest.getPath()).startsWith("/oauth2/token?grant_type=client_credentials");
		AssertionsForClassTypes.assertThat(recordedRequest.getMethod()).isEqualTo("POST");

		recordedRequest = mockWebServer.takeRequest();

		assertThat(recordedRequest.getMethod()).isEqualTo("GET");
		assertThat(recordedRequest.getPath()).startsWith("/users/");

		recordedRequest = mockWebServer.takeRequest();
		LOG.info("should be acesstoken path for recordedRequest: {}", recordedRequest.getPath());
		AssertionsForClassTypes.assertThat(recordedRequest.getPath()).startsWith("/oauth2/token?grant_type=client_credentials");
		AssertionsForClassTypes.assertThat(recordedRequest.getMethod()).isEqualTo("POST");

		recordedRequest = mockWebServer.takeRequest();
		assertThat(recordedRequest.getMethod()).isEqualTo("GET");
		assertThat(recordedRequest.getPath()).startsWith("/organizations/");//userExistsInOrganization http call

		recordedRequest = mockWebServer.takeRequest();
		assertThat(recordedRequest.getMethod()).isEqualTo("POST");
		assertThat(recordedRequest.getPath()).startsWith("/authentications/authenticate");
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
		this.webClient.getOptions().setRedirectEnabled(false);

		final String jwtString= "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJzb25hbSIsImlzcyI6InNvbmFtLmNsb3VkIiwiYXVkIjoic29uYW0uY2xvdWQiLCJqdGkiOiJmMTY2NjM1OS05YTViLTQ3NzMtOWUyNy00OGU0OTFlNDYzNGIifQ.KGFBUjghvcmNGDH0eM17S9pWkoLwbvDaDBGAx2AyB41yZ_8-WewTriR08JdjLskw1dsRYpMh9idxQ4BS6xmOCQ";

		final String jwtTokenMsg = " {\"access_token\":\""+jwtString+"\"}";
		mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
				.setResponseCode(200).setBody(jwtTokenMsg));

		mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
				.setResponseCode(200).setBody("{\"id\":\""+userId+"\", \"firstName\":\"Dommy\"}"));

		WebResponse response = this.webClient.getPage(AUTHORIZATION_REQUEST).getWebResponse();

		final String loginPage = response.getResponseHeaderValue("location");

		LOG.info("sign-in to the location page: {}", response
				.getResponseHeaderValue("location"));

		Page page = signIn(this.webClient.getPage(response
				.getResponseHeaderValue("location")), "user1", "password");
		//HTMLParser htmlParser = HTMLParser

		//LOG.info("textPage: {}", page.getUrl());

		LOG.info("assert we get back the same login page when client not found");
		//in future look for the error message in the htmlPage
		LOG.info("is html page: {}, url: {}, content: {}", page.isHtmlPage(), page.getUrl(), page.getWebResponse().getContentAsString());

		LOG.info("assert we got back the login page when clientId is not found");
		assertThat(page.getUrl().toString()).isEqualTo(loginPage);

		RecordedRequest recordedRequest = mockWebServer.takeRequest();
		LOG.info("should be acesstoken path for recordedRequest: {}", recordedRequest.getPath());
		AssertionsForClassTypes.assertThat(recordedRequest.getPath()).startsWith("/oauth2/token?grant_type=client_credentials");
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
		this.webClient.getOptions().setRedirectEnabled(false);

		WebResponse response = this.webClient.getPage(AUTHORIZATION_REQUEST).getWebResponse();
		final String jwtString= "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJzb25hbSIsImlzcyI6InNvbmFtLmNsb3VkIiwiYXVkIjoic29uYW0uY2xvdWQiLCJqdGkiOiJmMTY2NjM1OS05YTViLTQ3NzMtOWUyNy00OGU0OTFlNDYzNGIifQ.KGFBUjghvcmNGDH0eM17S9pWkoLwbvDaDBGAx2AyB41yZ_8-WewTriR08JdjLskw1dsRYpMh9idxQ4BS6xmOCQ";

		final String jwtTokenMsg = " {\"access_token\":\""+jwtString+"\"}";
		mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
				.setResponseCode(200).setBody(jwtTokenMsg));

		//this response is for getting user by authenticationId (loginId)
		mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
				.setResponseCode(400).setBody("{\"error\":\"user not found\"}"));


		signIn(this.webClient.getPage(response
				.getResponseHeaderValue("location")), "user1", "password");

		LOG.info("take request");
		RecordedRequest recordedRequest = mockWebServer.takeRequest();

		LOG.info("should be acesstoken path for recordedRequest: {}", recordedRequest.getPath());
		AssertionsForClassTypes.assertThat(recordedRequest.getPath()).startsWith("/oauth2/token?grant_type=client_credentials");
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
		this.webClient.getOptions().setRedirectEnabled(false);


		//save User uuid with clientId
		saveClientUser(clientId, userId);
		final String jwtString= "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJzb25hbSIsImlzcyI6InNvbmFtLmNsb3VkIiwiYXVkIjoic29uYW0uY2xvdWQiLCJqdGkiOiJmMTY2NjM1OS05YTViLTQ3NzMtOWUyNy00OGU0OTFlNDYzNGIifQ.KGFBUjghvcmNGDH0eM17S9pWkoLwbvDaDBGAx2AyB41yZ_8-WewTriR08JdjLskw1dsRYpMh9idxQ4BS6xmOCQ";

		final String jwtTokenMsg = " {\"access_token\":\""+jwtString+"\"}";
		mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
				.setResponseCode(200).setBody(jwtTokenMsg));

		//mock response for user-id http callout
		mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
				.setResponseCode(200).setBody("{\"id\":\""+userId+"\", \"firstName\":\"Dommy\"}"));

		// user will be found from clientUser relationship
		//mock role names for authentication http callout
		mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
				.setResponseCode(200).setBody("{\"roleNames\": \"[user, SuperAdmin]\", \"message\": \"Authentication successful\"}"));

		WebResponse response = this.webClient.getPage(AUTHORIZATION_REQUEST).getWebResponse();

		LOG.info("sign-in to the location page");

		//login should work for client as client should be found in ClientUser relationship
		signIn(this.webClient.getPage(response
				.getResponseHeaderValue("location")), "user1", "password");
		RecordedRequest recordedRequest = mockWebServer.takeRequest();

		LOG.info("should be acesstoken path for recordedRequest: {}", recordedRequest.getPath());
		AssertionsForClassTypes.assertThat(recordedRequest.getPath()).startsWith("/oauth2/token?grant_type=client_credentials");
		AssertionsForClassTypes.assertThat(recordedRequest.getMethod()).isEqualTo("POST");

		recordedRequest = mockWebServer.takeRequest();

		assertThat(recordedRequest.getMethod()).isEqualTo("GET");
		assertThat(recordedRequest.getPath()).startsWith("/users/");

		recordedRequest = mockWebServer.takeRequest();
		assertThat(recordedRequest.getMethod()).isEqualTo("POST");
		assertThat(recordedRequest.getPath()).startsWith("/authentications/authenticate");
	}

	private static <P extends Page> P signIn(HtmlPage page, String username, String password) throws IOException {
		//LOG.info("page: {}, done end", page.toString());
		HtmlInput usernameInput = page.querySelector("input[name=\"username\"]");
		HtmlInput passwordInput = page.querySelector("input[name=\"password\"]");
		HtmlButton signInButton = page.querySelector("button");

		usernameInput.type(username);
		passwordInput.type(password);
		return signInButton.click();
	}

	private static void assertLoginPage(HtmlPage page) {
		assertThat(page.getUrl().toString()).endsWith("/login");

		HtmlInput usernameInput = page.querySelector("input[name=\"username\"]");
		HtmlInput passwordInput = page.querySelector("input[name=\"password\"]");
		HtmlButton signInButton = page.querySelector("button");

		assertThat(usernameInput).isNotNull();
		assertThat(passwordInput).isNotNull();
		assertThat(signInButton.getTextContent()).isEqualTo("Sign in");
	}

}
