package me.sonam.auth.config;

import me.sonam.auth.service.OidcUserInfoService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;


@Configuration
public class IdTokenCustomizerConfig {
    private static final Logger LOG = LoggerFactory.getLogger(IdTokenCustomizerConfig.class);

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(
            OidcUserInfoService userInfoService) {
        LOG.info("load user hello");

        return (context) -> {
            if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
                OidcUserInfo userInfo = userInfoService.loadUser(
                        context.getPrincipal().getName());
                LOG.info("userInfo: {}, principal.name: {}", userInfo, context.getPrincipal().getName());
                context.getClaims().claims(claims ->
                        claims.putAll(userInfo.getClaims()));
            }
        };
    }

}