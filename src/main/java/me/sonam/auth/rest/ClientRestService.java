package me.sonam.auth.rest;


import jakarta.ws.rs.BadRequestException;
import me.sonam.auth.jpa.entity.Client;
import me.sonam.auth.jpa.entity.ClientOwner;
import me.sonam.auth.jpa.entity.ClientUser;
import me.sonam.auth.jpa.entity.TokenMediate;
import me.sonam.auth.jpa.repo.*;
import me.sonam.auth.rest.util.MyPair;
import me.sonam.auth.service.JpaRegisteredClientRepository;
import me.sonam.auth.util.TokenRequestFilter;
import me.sonam.auth.webclient.TokenMediatorWebClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.*;

@RestController
@RequestMapping("/clients")
public class ClientRestService {
    private static final Logger LOG = LoggerFactory.getLogger(ClientRestService.class);


    private ClientRepository clientRepository;
    private final JpaRegisteredClientRepository jpaRegisteredClientRepository;
    @Autowired
    private TokenMediateRepository tokenMediateRepository;

    @Autowired
    private HClientUserRepository clientUserRepository;

    @Autowired
    private ClientOrganizationRepository clientOrganizationRepository;

    @Autowired
    private ClientOwnerRepository clientOwnerRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private TokenRequestFilter tokenRequestFilter;

    private TokenMediatorWebClient tokenMediatorWebClient;

    public ClientRestService(JpaRegisteredClientRepository jpaRegisteredClientRepository,
                             ClientRepository clientRepository, PasswordEncoder passwordEncoder,
                             TokenMediatorWebClient tokenMediatorWebClient) {
        this.tokenMediatorWebClient = tokenMediatorWebClient;
        this.jpaRegisteredClientRepository = jpaRegisteredClientRepository;
        this.clientRepository = clientRepository;
        this.passwordEncoder = passwordEncoder;
        LOG.info("initialized clientRestService");
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Map<String, Object> createNew(@RequestBody Map<String, Object> map) {
        LOG.info("create new client with map: {}", map);

        Jwt jwt = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String userIdString = jwt.getClaim("userId");

        String accessToken = jwt.getTokenValue();

        UUID userId = UUID.fromString(userIdString);

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

        LOG.info("saving bcrypt encodedPassword {} as the clientSecret", encodedPassword);
        map.put("clientSecret", encodedPassword);

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
            tokenMediatorWebClient.saveClientInTokenMediator(accessToken, map.get("clientId").toString(), map.get("clientSecret").toString())
                    .block();
        }
        else {
            if (tokenMediateRepository.existsById(clientId)) {
                LOG.info("delete existing tokenMediate record when not enabled.");
                tokenMediateRepository.deleteById(clientId);
            }
            tokenMediatorWebClient.deleteClientFromTokenMediator(accessToken, map.get("clientId").toString()).block();
        }

        LOG.info("save clientUser relationship");
        clientUserRepository.save(new ClientUser(UUID.fromString(registeredClient.getId()),
                UUID.fromString(map.get("userId").toString())));

        Map<String, Object> mapToReturn = jpaRegisteredClientRepository.getMapObject(registeredClient, false);
        //mapToReturn.put("mediateToken", Boolean.toString(mediateToken));

        LOG.info("clientId: {}", clientId);

        clientOwnerRepository.save(new ClientOwner(clientId, userId));

        return mapToReturn;
    }

    @RequestMapping(value = "/client-id/{clientId}",  method=RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public Map<String, Object> getByClientId(@PathVariable("clientId") String clientId) {
        LOG.info("get by clientId: {}", clientId);

        RegisteredClient registeredClient = jpaRegisteredClientRepository.findByClientId(clientId);
        boolean exists = tokenMediateRepository.existsById(UUID.fromString(registeredClient.getId()));
        return jpaRegisteredClientRepository.getMapObject(registeredClient, exists);
    }

    @GetMapping(value = "{id}")
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


    @GetMapping("/users/{id}")
    @ResponseStatus(HttpStatus.OK)
    public Page<MyPair<String, String>> getClientsOwnedByUserId(@PathVariable("id") UUID userId, Pageable pageable) {
        LOG.info("get clientIds for userId: {}", userId);

        Jwt jwt = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String userIdString = jwt.getClaim("userId");
        UUID ownerId = UUID.fromString(userIdString);

        LOG.info("userIdString: {}, and userId: {}",userIdString, userId);
        LOG.info("jwt.getTokenValue: {}", jwt.getTokenValue());

        List<MyPair<String, String>> list = new ArrayList<>();

        clientOwnerRepository.findByUserId(userId, pageable).forEach(clientOwner -> {
                    Optional<Client> optionalClient = clientRepository.findById(clientOwner.getClientId().toString());
                    if (optionalClient.isEmpty()) {
                        LOG.error("client not found ClientRepository by clientId: '{}'", clientOwner.getClientId());
                    }
                    optionalClient.ifPresent(client ->
                            list.add(new MyPair<>(client.getId(), client.getClientId())));
                }
        );

       /* clientUserRepository.findByUserId(userId, pageable).forEach(clientUser -> {
                    Optional<Client> optionalClient = clientRepository.findById(clientUser.getClientId().toString());
                    if (optionalClient.isEmpty()) {
                        LOG.error("client not found ClientRepository by clientId: '{}'", clientUser.getClientId());
                    }
                    optionalClient.ifPresent(client ->
                            list.add(new MyPair<>(client.getId(), client.getClientId())));
                }
        );*/

        LOG.info("list of clientId pairs: {}", list);
        return new PageImpl<>(list, pageable, clientOwnerRepository.countByUserId(userId));
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
        LOG.info("clientIdIssuedAt: {}", map.get("clientIdIssuedAt"));

        Jwt jwt = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        String accessToken = jwt.getTokenValue();
        LOG.info("accessToken: {}", accessToken);

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
        final String newClientSecret = (String) map.get("newClientSecret");
        LOG.info("using newClientSecret as clientSecret: {}", newClientSecret);

        if (newClientSecret != null && !newClientSecret.isEmpty()) {

            LOG.info("using new client secret to overwrite clientSecret: {}", map.get("newClientSecret"));
            final String encodedPassword = passwordEncoder.encode(newClientSecret);
            map.put("clientSecret", encodedPassword);
            LOG.info("adding encodePassword as clientSecret: {}", encodedPassword);
        }

        LOG.info("fromDb: {}, fromDb.ts.authCodeTimeToLive seconds: {}",
                fromDb, fromDb.getTokenSettings().getAuthorizationCodeTimeToLive().getSeconds());

        try {
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
                if (newClientSecret != null && !newClientSecret.isEmpty()) {
                    LOG.info("newClientSecret is set in plain text, so call token mediator");
                    return tokenMediatorWebClient.saveClientInTokenMediator(accessToken, map.get("clientId").toString(), newClientSecret)
                            .map(map1 -> jpaRegisteredClientRepository.findByClientId(registeredClient.getClientId()))
                            .map(registeredClient1 -> jpaRegisteredClientRepository.getMapObject(registeredClient1, false));
                }
                else {
                    RegisteredClient registeredClient1 = jpaRegisteredClientRepository.findByClientId(registeredClient.getClientId());
                    return Mono.just(jpaRegisteredClientRepository.getMapObject(registeredClient1, false));
                }
            }
            else {
                if (tokenMediateRepository.existsById(clientId)) {
                    LOG.info("delete existing tokenMediate record when not enabled.");
                    tokenMediateRepository.deleteById(clientId);
                }
                LOG.debug("call to delete client from tokenMediator and return map object");
                return tokenMediatorWebClient.deleteClientFromTokenMediator(accessToken, map.get("clientId").toString())
                        .thenReturn(jpaRegisteredClientRepository.getMapObject(registeredClient, false));//Boolean.parseBoolean(map.get("mediateToken").toString())));
            }
        }
        catch (Exception e) {
            LOG.error("exception can occur if user does not fill right data {}", e.getMessage(), e);
            return Mono.error(new BadRequestException("update failed: "+ e.getMessage()));
        }
    }

    @DeleteMapping("{id}/user-id/{userId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Transactional
    public Mono<Void> delete(@PathVariable("id") String id, @PathVariable("userId") UUID userId) {
        LOG.info("delete client with id: {}", id);

        Jwt jwt = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        String accessToken = jwt.getTokenValue();
        LOG.info("accessToken: {}", accessToken);

        RegisteredClient registeredClient = jpaRegisteredClientRepository.findById(id);

        if (registeredClient == null) {
            LOG.error("client not found with id: {}", id);
            return Mono.empty();
        }
        else {

            verifyUserOwnsClientId(UUID.fromString(id), userId);

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
            return tokenMediatorWebClient.deleteClientFromTokenMediator(accessToken, registeredClient.getClientId())
                        .then();
        }
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
