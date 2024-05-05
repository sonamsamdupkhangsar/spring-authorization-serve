package me.sonam.auth.rest;

import me.sonam.auth.service.AuthenticationCallout;
import me.sonam.auth.util.UserId;
import okhttp3.Response;
import org.apache.catalina.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * this controller will use the AuthenticationCallout service to login a user.
 * This should be replaced with pkce oauth client for authenitcation.
 */
@RestController
@RequestMapping("/authenticate")
public class AuthenticateRestController {
    private static final Logger LOG = LoggerFactory.getLogger(AuthenticateRestController.class);

    @Autowired
    private AuthenticationCallout authenticationCallout;

    @PutMapping
    public ResponseEntity<Map<String, Object>> authenticate(@RequestBody Map<String, String> map) {
        LOG.info("authenticate using rest client: {}", map);

        try {
            Authentication authentication = authenticationCallout.restAuth(new
                    UsernamePasswordAuthenticationToken(map.get("username"), map.get("password")), map.get("clientId"));
            StringBuilder stringBuilder = new StringBuilder();
            if (authentication != null) {
                authentication.getAuthorities().forEach(grantedAuthority ->
                        stringBuilder.append(grantedAuthority.getAuthority()).append(" "));
            }

            LOG.info("returning roles: {}", stringBuilder);
            UserId userId = (UserId) authentication.getPrincipal();
            LOG.info("userId: {}", userId.getUserId());

            return ResponseEntity.status(HttpStatus.OK).body(Map.of("message", "authentication success",
                    "roles", stringBuilder.toString(),
                        "userId", userId.getUserId().toString()));
        }
        catch (Exception e) {
            LOG.error("exception occured in authentication: {}", e.getMessage(), e);
            //return Map.of("error", "not authtenticated");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", "authentication failed"));
        }
    }
}
