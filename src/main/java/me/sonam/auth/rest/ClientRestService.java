package me.sonam.auth.rest;

import jakarta.ws.rs.BadRequestException;
import me.sonam.auth.jpa.entity.Client;
import me.sonam.auth.jpa.entity.TokenMediate;
import me.sonam.auth.jpa.repo.ClientRepository;
import me.sonam.auth.jpa.repo.TokenMediateRepository;
import me.sonam.auth.service.JpaRegisteredClientRepository;
import me.sonam.auth.service.TokenService;
import me.sonam.auth.util.JwtPath;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

@RestController
@RequestMapping("/clients")
public class ClientRestService {
    private static final Logger LOG = LoggerFactory.getLogger(ClientRestService.class);

    @Value("${token-mediator.root}${token-mediator.clients}")
    private String tokenMediatorEndpoint;

    private ClientRepository clientRepository;
    private final JpaRegisteredClientRepository jpaRegisteredClientRepository;
    @Autowired
    private TokenMediateRepository tokenMediateRepository;

    private WebClient.Builder webClientBuilder;

    @Autowired
    private JwtPath jwtPath;
    @Autowired
    private TokenService tokenService;

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
        return clientId;
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
    public Map<String, String> update(@RequestBody Map<String, Object> map) {
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
                            return Mono.just(Map.of("message", "deleted client in authorization-server," +
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

    private Mono<Map> saveClientInTokenMediator(String clientId, String password) {
        LOG.info("save client in tokenMediator");

        if (!jwtPath.getJwtRequest().isEmpty()) {
            JwtPath.JwtRequest.AccessToken accessToken = jwtPath.getJwtRequest().get(0).getAccessToken();
            Mono<String> accessTokenMono = tokenService.getSystemAccessTokenUsingClientCredential(accessToken);

            return accessTokenMono.flatMap(stringAccessToken -> {
                LOG.info("use the access token: {}", stringAccessToken);
                WebClient.ResponseSpec responseSpec = webClientBuilder.build().put().uri(tokenMediatorEndpoint)
                        .headers(httpHeaders -> httpHeaders.setBearerAuth(stringAccessToken))
                        .bodyValue(Map.of("clientId", clientId, "clientSecret", password))
                        .accept(MediaType.APPLICATION_JSON)
                        .retrieve();
                return responseSpec.bodyToMono(Map.class).
                        onErrorResume(throwable -> {
                    LOG.error("failed to save clientId and clientSecret in token-mediator");
                    return Mono.just(Map.of("error", "failed to save client in token-mediator"));
                });
            });
        }
        else{
            return Mono.just(Map.of("error", "jwt request map is empty, client-secret not saved in token-mediator"));
        }
    }

    private Mono<Map> deleteClientFromTokenMediator(String clientId) {
        LOG.info("delete client from tokenMediator");

        if (!jwtPath.getJwtRequest().isEmpty()) {
            JwtPath.JwtRequest.AccessToken accessToken = jwtPath.getJwtRequest().get(0).getAccessToken();
            Mono<String> accessTokenMono = tokenService.getSystemAccessTokenUsingClientCredential(accessToken);
            String deleteTokenEndpoint = new StringBuilder(tokenMediatorEndpoint).append("/").append(clientId).toString();

            return accessTokenMono.flatMap(stringAccessToken -> {
                LOG.info("use the access token: {}", stringAccessToken);
                WebClient.ResponseSpec responseSpec = webClientBuilder.build().delete().uri(deleteTokenEndpoint)
                        .headers(httpHeaders -> httpHeaders.setBearerAuth(stringAccessToken))
                        .accept(MediaType.APPLICATION_JSON)
                        .retrieve();
               return responseSpec.bodyToMono(Map.class)
                        .onErrorResume(throwable -> {
                            LOG.error("failed to delete clientId in token-mediator: {}", throwable.getMessage());
                            return Mono.just(Map.of("error", "failed to delete client in token-mediator"));
                        });
            });
        }
        else {
            return Mono.just(Map.of("error", "jwt request map is empty, not calling token-mediator"));
        }
    }
}
