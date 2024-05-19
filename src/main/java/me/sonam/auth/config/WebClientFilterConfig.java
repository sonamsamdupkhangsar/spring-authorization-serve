package me.sonam.auth.config;

import jakarta.annotation.PostConstruct;
import me.sonam.auth.AccountWebClient;
import me.sonam.auth.service.TokenFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class WebClientFilterConfig {
    private static final Logger LOG = LoggerFactory.getLogger(WebClientFilterConfig.class);

    @Value("${account-rest-service.root}${account-rest-service.context}${account-rest-service.emailActivateLink}")
    private String emailActiveLink;

    @Value("${account-rest-service.root}${account-rest-service.context}${account-rest-service.emailMySecret}")
    private String emailMySecret;
    @Value("${account-rest-service.root}${account-rest-service.context}${account-rest-service.emailUsername}")
    private String emailUsername;
    @Value("${account-rest-service.root}${account-rest-service.context}${account-rest-service.validateEmailLoginSecret}")
    private String validateEmailLoginSecret;
    @Value("${account-rest-service.root}${account-rest-service.context}${account-rest-service.updatePassword}")
    private String updatePassword;

    @Autowired
    private WebClient.Builder webCliBuilder;

    @Autowired
    private TokenFilter tokenFilter;

    @PostConstruct
    public void addFilterToWebClient() {
        LOG.info("configure the renewTokenFilter only once in this config");
        webCliBuilder.filter(tokenFilter.renewTokenFilter()).build();
    }

    @Bean
    public AccountWebClient accountWebClient() {
        return new AccountWebClient(webCliBuilder, emailUsername, emailMySecret, emailActiveLink, validateEmailLoginSecret, updatePassword);
    }

}
