package me.sonam.auth.webtestclient;

import me.sonam.auth.jpa.entity.ClientOrganization;
import me.sonam.auth.rest.util.MyPair;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.util.List;
import java.util.UUID;


public class ClientOrganizationWebTestClient {
    private static final Logger LOG = LoggerFactory.getLogger(ClientOrganizationWebTestClient.class);

    private WebTestClient webTestClient;

    private String clientOrganizationEndpoint = "/clients/organizations";

    public ClientOrganizationWebTestClient(WebTestClient webTestClient) {
        this.webTestClient = webTestClient;
    }

    public String associateClientWithOrganization(String accessToken, ClientOrganization clientOrganization, HttpStatus httpStatus) {
        return webTestClient.post().uri(clientOrganizationEndpoint).bodyValue(clientOrganization)
                .headers(httpHeaders -> httpHeaders.setBearerAuth(accessToken))
                .exchange().expectStatus().isEqualTo(httpStatus).expectBody(String.class).returnResult().getResponseBody();
    }

    public ClientOrganization findRow(String accessToken, UUID clientId, UUID organizationId, HttpStatus httpStatus) {
        return webTestClient.put().uri(clientOrganizationEndpoint).bodyValue(new MyPair<>(clientId, List.of(organizationId)))
                .headers(httpHeaders -> httpHeaders.setBearerAuth(accessToken))
                .accept(MediaType.APPLICATION_JSON)
                .exchange().expectStatus().isEqualTo(httpStatus).expectBody(ClientOrganization.class).returnResult().getResponseBody();
    }

    public String findEmptyRow(String accessToken, UUID clientId, UUID organizationId, HttpStatus httpStatus) {
        return webTestClient.put().uri(clientOrganizationEndpoint).bodyValue(new MyPair<>(clientId, List.of(organizationId)))
                .headers(httpHeaders -> httpHeaders.setBearerAuth(accessToken))
                .accept(MediaType.APPLICATION_JSON)
                .exchange().expectStatus().isEqualTo(httpStatus).expectBody(String.class).returnResult().getResponseBody();
    }

    public String delete(String accessToken, UUID clientId, UUID organizationId, HttpStatus httpStatus) {
        return webTestClient.delete().uri("/clients/"+clientId+"/organizations/"+organizationId)
                .headers(httpHeaders -> httpHeaders.setBearerAuth(accessToken))
                .exchange().expectStatus().isEqualTo(httpStatus).expectBody(String.class).returnResult().getResponseBody();
    }

    public UUID getOrganizationIdForClientId(String accessToken, UUID clientId, HttpStatus httpStatus) {
        return webTestClient.get().uri("/clients/"+clientId+"/organizations/id")
                .headers(httpHeaders -> httpHeaders.setBearerAuth(accessToken))
                .exchange().expectStatus().isEqualTo(httpStatus).expectBody(UUID.class).returnResult().getResponseBody();
    }
}
