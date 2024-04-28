package me.sonam.auth.rest;



import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.Path;
import kotlin.collections.ArrayDeque;
import me.sonam.auth.jpa.entity.ClientOrganization;
import me.sonam.auth.jpa.entity.ClientUser;
import me.sonam.auth.jpa.entity.TokenMediate;
import me.sonam.auth.jpa.repo.ClientOrganizationRepository;
import me.sonam.auth.jpa.repo.ClientRepository;
import me.sonam.auth.jpa.repo.HClientUserRepository;
import me.sonam.auth.jpa.repo.TokenMediateRepository;
import me.sonam.auth.rest.util.MyPair;
import me.sonam.auth.service.JpaRegisteredClientRepository;
import me.sonam.auth.util.JwtPath;
import me.sonam.auth.util.UserId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.util.Pair;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.*;
import java.util.stream.Collectors;

import static reactor.core.publisher.Mono.just;

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

    @Autowired
    private ClientOrganizationRepository clientOrganizationRepository;
    private WebClient.Builder webClientBuilder;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtPath jwtPath;

    public ClientRestService(WebClient.Builder webClientBuilder,
                             JpaRegisteredClientRepository jpaRegisteredClientRepository,
                             ClientRepository clientRepository, PasswordEncoder passwordEncoder) {
        this.webClientBuilder = webClientBuilder;
        this.jpaRegisteredClientRepository = jpaRegisteredClientRepository;
        this.clientRepository = clientRepository;
        this.passwordEncoder = passwordEncoder;
        LOG.info("initialized clientRestService");
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Map<String, Object> createNew(@RequestBody Map<String, Object> map ) {
        LOG.info("create new client with map: {}", map);

        if (jpaRegisteredClientRepository.findByClientId(map.get("clientId").toString()) != null) {
            LOG.error("clientId already exists, do an update");
            //throw new BadRequestException("clientId already exists");
            RegisteredClient registeredClient = jpaRegisteredClientRepository.findByClientId(map.get("clientId").toString());
            if (registeredClient != null) {
                return jpaRegisteredClientRepository.getMapObject(registeredClient, false);
            }
            throw new BadRequestException("clientId already exists but not able to pull from repository");
        }

        String encodedPassword = passwordEncoder.encode((String)map.get("clientSecret"));
        LOG.info("encodedPassword: {}", encodedPassword);
        map.put("clientSecret", encodedPassword);
        LOG.info("encode password with bcrypt");
        RegisteredClient registeredClient = jpaRegisteredClientRepository.build(map);

        LOG.debug("built registeredClient from map: {}", registeredClient);

        jpaRegisteredClientRepository.save(registeredClient);
        RegisteredClient savedRedisteredClient = jpaRegisteredClientRepository.findById(registeredClient.getId());
        LOG.info("saved registeredClient: {}", savedRedisteredClient);

        LOG.info("saved registeredClient.id: {}", registeredClient.getId());
        UUID clientId = UUID.fromString(registeredClient.getId());
        boolean mediateToken = false;
        if (map.get("mediateToken") != null) {
            mediateToken = Boolean.parseBoolean(map.get("mediateToken").toString());
        }

        if (mediateToken) {
            if (!tokenMediateRepository.existsById(clientId)) {
                TokenMediate tokenMediate = new TokenMediate(UUID.fromString(registeredClient.getId()));
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
        clientUserRepository.save(new ClientUser(UUID.fromString(registeredClient.getId()),
                UUID.fromString(map.get("userId").toString())));

        Map<String, Object> mapToReturn = jpaRegisteredClientRepository.getMapObject(registeredClient, false);
        mapToReturn.put("mediateToken", Boolean.toString(mediateToken));
        return mapToReturn;
    }

    @GetMapping("clientId/{clientId}")
    @ResponseStatus(HttpStatus.OK)
    public Map<String, Object> getByClientId(@PathVariable("clientId") String clientId) {
        LOG.info("get by clientId: {}", clientId);

        RegisteredClient registeredClient = jpaRegisteredClientRepository.findByClientId(clientId);
        boolean exists = tokenMediateRepository.existsById(UUID.fromString(registeredClient.getId()));
        return jpaRegisteredClientRepository.getMapObject(registeredClient, exists);
    }

    @GetMapping("id/{id}")
    @ResponseStatus(HttpStatus.OK)
    public Map<String, Object> getClientById(@PathVariable("id") String id) {
        LOG.info("get client by id: {}", id);

        RegisteredClient registeredClient = jpaRegisteredClientRepository.findById(id);
        boolean exists = false;
        if (registeredClient != null) {
            exists = tokenMediateRepository.existsById(UUID.fromString(registeredClient.getId()));
            return jpaRegisteredClientRepository.getMapObject(registeredClient, exists);
        }
        return Map.of("error", "registeredClient not found with id:"+ id);
    }


    @GetMapping("/user/userId/{userId}")
    @ResponseStatus(HttpStatus.OK)
    public List<MyPair<String, String>> getClientIdsByUser(@PathVariable("userId") UUID userId) {
        LOG.info("get clientIds for userId: {}", userId);

        List<MyPair<String, String>> list = new ArrayList<>();

        clientUserRepository.findByUserId(userId).forEach(clientUser ->
                clientRepository.findById(clientUser.getClientId().toString())
                        .ifPresent(client ->
                            list.add(new MyPair<>(client.getId(), client.getClientId()))));
        LOG.info("list of clientId pairs: {}", list);
        return list;
/*
        List<ClientUser> clientUserList =clientUserRepository.findByUserId(userId).stream()
                .toList();
        return clientUserList.stream().map(ClientUser::getClientId).toList();
*/
    }

    @PutMapping
    @ResponseStatus(HttpStatus.OK)
    public Mono<Map<String, Object>> update(@RequestBody Map<String, Object> map) {
        LOG.info("update client using map: {}", map);

        if (map.get("id") == null) {
            LOG.error("map does not contain client id");
            return Mono.error(new BadRequestException("No client id"));
        }
        RegisteredClient fromDb = jpaRegisteredClientRepository.findById(map.get("id").toString());
        if (fromDb == null) {
            LOG.error("There is no RegisteredClient found with id: {}", map.get("id"));
            return Mono.error(new BadRequestException("Registered client not found with id: "+map.get("id")));
        }

        verifyUserOwnsClientId(UUID.fromString(fromDb.getId()), UUID.fromString(map.get("userId").toString()));

        //RegisteredClient fromDb = jpaRegisteredClientRepository.findByClientId((String)map.get("clientId"));
        map.put("id", fromDb.getId());

        LOG.info("fromDb: {}, fromDb.ts.authCodeTimeToLive seconds: {}",
                fromDb, fromDb.getTokenSettings().getAuthorizationCodeTimeToLive().getSeconds());

        try {
           /* String encodedPassword = passwordEncoder.encode((String)map.get("clientSecret"));
            LOG.info("encodedPassword: {}", encodedPassword);
            map.put("clientSecret", encodedPassword);
            LOG.info("encode password with bcrypt");*/
            RegisteredClient registeredClient = jpaRegisteredClientRepository.build(map);

            LOG.info("built registeredClient from map, authorizationCodeTimeToLive in seconds: {}, registeredClient",
                    registeredClient.getTokenSettings().getAuthorizationCodeTimeToLive().getSeconds(), registeredClient);

            jpaRegisteredClientRepository.save(registeredClient);

            LOG.info("saved registeredClient entity");
            UUID clientId = UUID.fromString(registeredClient.getId());

            if (map.get("mediateToken") != null && Boolean.parseBoolean(map.get("mediateToken").toString()) == true) {
                if (!tokenMediateRepository.existsById(clientId)) {
                    TokenMediate tokenMediate = new TokenMediate(clientId);
                    tokenMediateRepository.save(tokenMediate);
                }
                return saveClientInTokenMediator(map.get("clientId").toString(), map.get("clientSecret").toString())
                        .map(map1 -> jpaRegisteredClientRepository.findByClientId(registeredClient.getClientId()))
                        .map(registeredClient1 -> jpaRegisteredClientRepository.getMapObject(registeredClient1, Boolean.parseBoolean(map.get("mediateToken").toString())));
            }
            else {
                if (tokenMediateRepository.existsById(clientId)) {
                    LOG.info("delete existing tokenMediate record when not enabled.");
                    tokenMediateRepository.deleteById(clientId);
                }
                return deleteClientFromTokenMediator(map.get("clientId").toString())
                        .thenReturn(jpaRegisteredClientRepository.getMapObject(registeredClient, Boolean.parseBoolean(map.get("mediateToken").toString())));
            }
        }
        catch (Exception e) {
            LOG.error("exception can occur if user does not fill right data {}", e.getMessage());
            return Mono.error(new BadRequestException("update failed: "+ e.getMessage()));
        }
    }

    @DeleteMapping("/id/{id}/ownerId/{ownerId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Transactional
    public Mono<Void> delete(@PathVariable("id") String id, @PathVariable("ownerId") UUID ownerId) {
        LOG.info("delete client with id: {}", id);

        RegisteredClient registeredClient = jpaRegisteredClientRepository.findById(id);

        if (registeredClient == null) {
            LOG.error("client not found with id: {}", id);
            return Mono.empty();
        }
        else {

            verifyUserOwnsClientId(UUID.fromString(id), ownerId);

            LOG.info("deleting by id: {}", registeredClient.getId());
            clientRepository.deleteById(registeredClient.getId());

            long rows = clientUserRepository.deleteByClientId(UUID.fromString(registeredClient.getId()));
            LOG.info("delete clientUser by clientId: {} affected rows: {}", registeredClient.getClientId(), rows);
            clientOrganizationRepository.deleteByClientId(UUID.fromString(registeredClient.getId()));

            clientUserRepository.deleteByClientId(UUID.fromString(registeredClient.getId()));

            if (tokenMediateRepository.existsById(UUID.fromString(registeredClient.getId()))) {
                LOG.info("delete tokenMediate for clientId");
                tokenMediateRepository.deleteById(UUID.fromString(registeredClient.getId()));
            }
            return deleteClientFromTokenMediator(registeredClient.getClientId())
                        .then();
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
                    return just(Map.of("error", "failed to save client in token-mediator"));
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
                    return just(Map.of("error", "failed to delete client in token-mediator"));
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

    private void verifyUserOwnsClientId(UUID clientId, UUID userId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        Optional<Boolean> booleanOptional = clientUserRepository.existsByClientIdAndUserId(clientId, userId);
        if(booleanOptional.isEmpty()) {
            LOG.error("logged-in user is not associated with clientId");
            throw new BadRequestException("Logged-in user and clientId must match");
        }

        booleanOptional.ifPresent(aBoolean -> {
            if (!aBoolean) {
                LOG.error("logged-in userId {} is not associated with clientId: {}", userId, clientId);
                throw new BadRequestException("Logged-in user and clientId must match");
            }
            else {
                LOG.info("there is a relationship between the clientId and userId: {}", aBoolean);
            }
        });
    }
}
