package me.sonam.auth.rest;


import jakarta.ws.rs.BadRequestException;
import me.sonam.auth.jpa.entity.ClientUser;
import me.sonam.auth.jpa.entity.TokenMediate;
import me.sonam.auth.jpa.repo.ClientRepository;
import me.sonam.auth.jpa.repo.HClientUserRepository;
import me.sonam.auth.jpa.repo.TokenMediateRepository;
import me.sonam.auth.service.JpaRegisteredClientRepository;
import me.sonam.auth.util.JwtPath;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/clients")
public class ClientRestService {
    private static final Logger LOG = LoggerFactory.getLogger(ClientRestService.class);

    @Value("${oauth2-token-mediator.root}${oauth2-token-mediator.clients}")
    private String tokenMediatorEndpoint;

    private ClientRepository clientRepository;
    private final JpaRegisteredClientRepository jpaRegisteredClientRepository;
    @Autowired
    private TokenMediateRepository tokenMediateRepository;

    @Autowired
    private HClientUserRepository clientUserRepository;
    private WebClient.Builder webClientBuilder;

    @Autowired
    private JwtPath jwtPath;

    public ClientRestService(WebClient.Builder webClientBuilder,
                             JpaRegisteredClientRepository jpaRegisteredClientRepository,
                             ClientRepository clientRepository) {
        this.webClientBuilder = webClientBuilder;
        this.jpaRegisteredClientRepository = jpaRegisteredClientRepository;
        this.clientRepository = clientRepository;
        LOG.info("initialized clientRestService");
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public String createNew(@RequestBody Map<String, Object> map ) {
        LOG.info("create new client");

        if (jpaRegisteredClientRepository.findByClientId(map.get("clientId").toString()) != null) {
            LOG.error("clientId already exists, do an update");
            throw new BadRequestException("clientId already exists");
        }

        RegisteredClient registeredClient = jpaRegisteredClientRepository.build(map);
        LOG.debug("built registeredClient from map: {}", registeredClient);

        jpaRegisteredClientRepository.save(registeredClient);
        LOG.info("saved registeredClient.id: {}", registeredClient.getClientId());
        String clientId = registeredClient.getClientId();

        if (map.get("mediateToken") != null && Boolean.parseBoolean(map.get("mediateToken").toString()) == true) {
            if (!tokenMediateRepository.existsById(clientId)) {
                TokenMediate tokenMediate = new TokenMediate(clientId);
                tokenMediateRepository.save(tokenMediate);
            }
            LOG.info("call tokenMediator");
            saveClientInTokenMediator(map.get("clientId").toString(), map.get("clientSecret").toString())
                    .block();
        }
        else {
            if (tokenMediateRepository.existsById(clientId)) {
                LOG.info("delete existing tokenMediate record when not enabled.");
                tokenMediateRepository.deleteById(clientId);
            }
            deleteClientFromTokenMediator(map.get("clientId").toString()).block();
        }

        LOG.info("save clientUser relationship");
        clientUserRepository.save(new ClientUser(map.get("clientId").toString(),
                UUID.fromString(map.get("userId").toString())));

        return clientId;
    }

    @GetMapping("{clientId}")
    @ResponseStatus(HttpStatus.OK)
    public Map<String, String> getByClientId(@PathVariable("clientId") String clientId) {
        LOG.info("get by clientId: {}", clientId);

        RegisteredClient registeredClient = jpaRegisteredClientRepository.findByClientId(clientId);
        return jpaRegisteredClientRepository.getMap(registeredClient);
    }


    @GetMapping("/user/{userId}")
    @ResponseStatus(HttpStatus.OK)
    public List<String> getClientIdsByUser(@PathVariable("userId") UUID userId) {
        LOG.info("get clientIds for userId: {}", userId);


        List<ClientUser> clientUserList =clientUserRepository.findByUserId(userId).stream()
                .toList();
        return clientUserList.stream().map(ClientUser::getClientId).toList();
    }

    @PutMapping
    @ResponseStatus(HttpStatus.OK)
    public Map<String, String> update(@RequestBody Map<String, Object> map) {
        LOG.info("check user id of the updater matches the clientId");

        checkClientIdAndLoggedInUser(map.get("clientId").toString());

        RegisteredClient fromDb = jpaRegisteredClientRepository.findByClientId((String)map.get("clientId"));
        map.put("id", fromDb.getId());

        RegisteredClient registeredClient = jpaRegisteredClientRepository.build(map);
        LOG.info("built registeredClient from map");

        jpaRegisteredClientRepository.save(registeredClient);
        LOG.info("saved registeredClient entity");
        String clientId = registeredClient.getClientId();

        if (map.get("mediateToken") != null && Boolean.parseBoolean(map.get("mediateToken").toString()) == true) {
            if (!tokenMediateRepository.existsById(clientId)) {
                TokenMediate tokenMediate = new TokenMediate(clientId);
                tokenMediateRepository.save(tokenMediate);
            }
            return saveClientInTokenMediator(map.get("clientId").toString(), map.get("clientSecret").toString())
                    .flatMap(clientMapResponse -> {
                        if (clientMapResponse.get("message") != null) {
                            return Mono.just(Map.of("message", "client updated in authorization server, "
                                    +clientMapResponse.get("message")));
                        } else if (clientMapResponse.get("error") != null) {
                            return Mono.just(Map.of("message", "client updated in authorization-server," +
                                    " " + clientMapResponse.get("error")));
                        } else {
                            return Mono.just(Map.of("message", "no message or error keys found"));
                        }
                    })
                    .block();
        }
        else {
            if (tokenMediateRepository.existsById(clientId)) {
                LOG.info("delete existing tokenMediate record when not enabled.");
                tokenMediateRepository.deleteById(clientId);
            }
            return deleteClientFromTokenMediator(map.get("clientId").toString())
                    .flatMap(clientMapResponse -> {
                        if (clientMapResponse.get("message") != null) {
                            return Mono.just(Map.of("message", "deleted client in token-mediator repo in authorization-server," +
                                    " " + clientMapResponse.get("message")));
                        } else if (clientMapResponse.get("error") != null) {
                            return Mono.just(Map.of("message", "deleted client in authorization-server," +
                                    " " + clientMapResponse.get("error")));
                        }
                        else {
                            return Mono.just(Map.of("message", "no message or error keys found"));
                        }
                    }).block();

        }
    }

    @DeleteMapping("/{clientId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Transactional
    public void delete(@PathVariable("clientId") String clientId) {
        LOG.info("delete client: {}", clientId);

        checkClientIdAndLoggedInUser(clientId);

        RegisteredClient registeredClient = jpaRegisteredClientRepository.findByClientId(clientId);
        if (registeredClient != null) {
            LOG.info("deleting by id: {}", registeredClient.getId());
            clientRepository.deleteById(registeredClient.getId());

            long rows = clientUserRepository.deleteByClientId(clientId);
            LOG.info("delete clientUser by clientId: {} affected rows: {}", clientId, rows);
        }
        else {
            LOG.error("registeredClient not found by clientId: {}", clientId);
        }
    }

    private Mono<Map> saveClientInTokenMediator(String clientId, String password) {
        LOG.info("save client in tokenMediator");
        WebClient.ResponseSpec responseSpec = webClientBuilder.build().put().uri(tokenMediatorEndpoint)
                .bodyValue(Map.of("clientId", clientId, "clientSecret", password))
                .accept(MediaType.APPLICATION_JSON)
                .retrieve();
        return responseSpec.bodyToMono(Map.class).
                onErrorResume(throwable -> {LOG.error("failed to save clientId and clientSecret in token-mediator");
                    return Mono.just(Map.of("error", "failed to save client in token-mediator"));
                });
    }

    private Mono<Map> deleteClientFromTokenMediator(String clientId) {
        LOG.info("delete client from tokenMediator");
        String deleteTokenEndpoint = new StringBuilder(tokenMediatorEndpoint).append("/").append(clientId).toString();

        WebClient.ResponseSpec responseSpec = webClientBuilder.build().delete().uri(deleteTokenEndpoint)
                .accept(MediaType.APPLICATION_JSON)
                .retrieve();
        return responseSpec.bodyToMono(Map.class)
                .onErrorResume(throwable -> {
                    LOG.error("failed to delete clientId in token-mediator: {}", throwable.getMessage());
                    return Mono.just(Map.of("error", "failed to delete client in token-mediator"));
                });
    }

    private void checkClientIdAndLoggedInUser(String clientId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        final String authId = authentication.getName();
        LOG.info("checking logged-in user: {} and clientId match: {}", authId.toString(), clientId);


        if(authId.equals(clientId)) {
            LOG.info("logged-in principal name and clientId matches");
        }
        else {
            LOG.error("logged-in principal and clientId does not match");
            throw new BadRequestException("Logged-in user and clientId must match");
        }
    }
}
