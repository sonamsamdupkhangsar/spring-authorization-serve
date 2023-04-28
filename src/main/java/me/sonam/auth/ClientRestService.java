package me.sonam.auth;

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
    public void createNew(@RequestBody RegisteredClient registeredClient) {
        registeredClient.withId(UUID.randomUUID().toString());

        jpaRegisteredClientRepository.save(registeredClient);
        LOG.info("saved registeredClient entity");
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

    @GetMapping("/clients/{id}")
    public RegisteredClient getById(@PathVariable String id) {
        LOG.info("get client by id: {}", id);
        return jpaRegisteredClientRepository.findById(id);
    }

    @GetMapping("/clients/{clientId}")
    public RegisteredClient getByClientId(@PathVariable String clientId) {
        LOG.info("get client by clientId: {}", clientId);
        return jpaRegisteredClientRepository.findByClientId(clientId);
    }
}
