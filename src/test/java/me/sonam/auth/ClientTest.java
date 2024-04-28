package me.sonam.auth;

import me.sonam.auth.jpa.entity.Client;
import me.sonam.auth.service.JpaRegisteredClientRepository;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.util.Map;
import java.util.UUID;

@SpringBootTest
public class ClientTest {

    private static final Logger LOG = LoggerFactory.getLogger(ClientTest.class);
    @Autowired
    private JpaRegisteredClientRepository jpaRegisteredClientRepository;

    @Test
    public void create() {
        RegisteredClient registeredClient = save("testclient", "secret");

        LOG.info("create new registeredClient: {}", registeredClient);

        Map<String, Object> map = jpaRegisteredClientRepository.getMapObject(registeredClient, true);
        LOG.info("map is {}", map);

        LOG.info("convert map to RegisteredClient");
        RegisteredClient registeredClient1 = jpaRegisteredClientRepository.build(map);
        LOG.info("built registeredClient1 from map with object: {}", registeredClient1);

    }

    @Test
    public void util() {
        LOG.info("use registeredClientUtil");

        RegisteredClientUtil registeredClientUtil = new RegisteredClientUtil();
        RegisteredClient registeredClient = save("testclient", "secret");

        LOG.info("create new registeredClient: {}", registeredClient);

        Map<String, Object> map = registeredClientUtil.getMapObject(registeredClient);
        LOG.info("registeredClientUtil map is {}", map);

        LOG.info("convert map to RegisteredClient");
        RegisteredClient registeredClient1 = registeredClientUtil.build(map);
        LOG.info("built registeredClient1 from map with object: {}", registeredClient1);
    }
    private RegisteredClient save(String clientId, String clientSecret) {

        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientSecret("{noop}"+clientSecret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
                .redirectUri("http://127.0.0.1:8080/authorized")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("message.read")
                .scope("message.write")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).requireProofKey(false).build())
                .build();
        jpaRegisteredClientRepository.save(registeredClient);

        return jpaRegisteredClientRepository.findByClientId(clientId);
    }
}
