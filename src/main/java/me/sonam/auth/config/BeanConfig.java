package me.sonam.auth.config;

import me.sonam.auth.webclient.UserWebClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class BeanConfig {

    @Bean
    public PasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }

    @Value("${user-rest-service.root}${user-rest-service.userByAuthId}")
    private String userByAuthIdEp;
    @Autowired
    private WebClient.Builder webClientBuilder;

    @Bean
    public UserWebClient userWebClient() {
        return new UserWebClient(webClientBuilder, userByAuthIdEp);
    }
}
