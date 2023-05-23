package me.sonam.auth.rest;

import me.sonam.auth.jpa.entity.Client;
import me.sonam.auth.service.JpaRegisteredClientRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
public class ClientRestService {
    private static final Logger LOG = LoggerFactory.getLogger(ClientRestService.class);

    private final JpaRegisteredClientRepository jpaRegisteredClientRepository;
    public ClientRestService(JpaRegisteredClientRepository jpaRegisteredClientRepository) {
        this.jpaRegisteredClientRepository = jpaRegisteredClientRepository;
    }

    @PostMapping("/clients")
    public String createNew(@RequestBody RegisteredClient registeredClient) {
        registeredClient.withId(UUID.randomUUID().toString());

        jpaRegisteredClientRepository.save(registeredClient);
        LOG.info("saved registeredClient entity");
        return registeredClient.getClientId();
    }

    @GetMapping("/clients/{clientId}")
    public RegisteredClient getByClientId(String clientId) {
        LOG.info("get by clientId: {}", clientId);
        RegisteredClient registeredClient = jpaRegisteredClientRepository.findByClientId(clientId);
        LOG.debug("for clientId: '{}', found registeredClient: {}", clientId, registeredClient);
        return registeredClient;
    }

    @PutMapping("/clients")
    public void update(@RequestBody RegisteredClient registeredClient) {
        if (registeredClient.getId() == null || registeredClient.getId().isEmpty()) {
            LOG.error("this is a new client, use the Post mapping");
        }
        else {
            registeredClient.withId(UUID.randomUUID().toString());

            jpaRegisteredClientRepository.save(registeredClient);
            LOG.info("saved registeredClient entity");
        }
    }

}
