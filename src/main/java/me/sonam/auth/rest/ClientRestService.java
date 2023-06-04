package me.sonam.auth.rest;

import me.sonam.auth.jpa.repo.ClientRepository;
import me.sonam.auth.service.JpaRegisteredClientRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/clients")
public class ClientRestService {
    private static final Logger LOG = LoggerFactory.getLogger(ClientRestService.class);

    private ClientRepository clientRepository;
    private final JpaRegisteredClientRepository jpaRegisteredClientRepository;

    public ClientRestService(JpaRegisteredClientRepository jpaRegisteredClientRepository, ClientRepository clientRepository) {
        this.jpaRegisteredClientRepository = jpaRegisteredClientRepository;
        this.clientRepository = clientRepository;
        LOG.info("initialized clientRestService");
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public String createNew(@RequestBody Map<String, Object> map ) {
        LOG.info("create new client");

        RegisteredClient registeredClient = jpaRegisteredClientRepository.build(map);
        LOG.debug("built registeredClient from map: {}", registeredClient);

        jpaRegisteredClientRepository.save(registeredClient);
        LOG.info("saved registeredClient.id: {}", registeredClient.getClientId());
        return registeredClient.getClientId();
    }

    @GetMapping("{clientId}")
    @ResponseStatus(HttpStatus.OK)
    public Map<String, String> getByClientId(@PathVariable("clientId") String clientId) {
        LOG.info("get by clientId: {}", clientId);

        RegisteredClient registeredClient = jpaRegisteredClientRepository.findByClientId(clientId);
        return jpaRegisteredClientRepository.getMap(registeredClient);
    }

    @PutMapping
    @ResponseStatus(HttpStatus.OK)
    public void update(@RequestBody Map<String, Object> map) {
        RegisteredClient fromDb = jpaRegisteredClientRepository.findByClientId((String)map.get("clientId"));
        map.put("id", fromDb.getId());

        RegisteredClient registeredClient = jpaRegisteredClientRepository.build(map);
        LOG.info("built registeredClient from map");

        jpaRegisteredClientRepository.save(registeredClient);
        LOG.info("saved registeredClient entity");
    }

    @DeleteMapping("/{clientId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable("clientId") String clientId) {
        LOG.info("delete client: {}", clientId);
        RegisteredClient registeredClient = jpaRegisteredClientRepository.findByClientId(clientId);
        if (registeredClient != null) {
            LOG.info("deleting by id: {}", registeredClient.getId());
            clientRepository.deleteById(registeredClient.getId());
        }
        else {
            LOG.error("registeredClient not found by clientId: {}", clientId);
        }
    }

}
