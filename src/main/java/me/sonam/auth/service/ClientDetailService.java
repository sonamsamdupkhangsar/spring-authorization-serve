package me.sonam.auth.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.List;

@Service
public class ClientDetailService implements UserDetailsService {
    private static final Logger LOG = LoggerFactory.getLogger(ClientDetailService.class);

    private RequestCache requestCache;

    public ClientDetailService(RequestCache requestCache) {
        this.requestCache = requestCache;
    }
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        LOG.info("loading by username: {}", username);

        var clientId = getClientId(requestCache);
        LOG.info("clientId: {}", clientId);

        final Authentication auth = new UsernamePasswordAuthenticationToken("user", "password", List.of());
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();
        return user;
    }


    private static String getClientId(RequestCache requestCache) {
        var requestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        var request = requestAttributes.getRequest();
        var response = requestAttributes.getResponse();
        var savedRequest = requestCache.getRequest(request, response);
        return getParameter(savedRequest, OAuth2ParameterNames.CLIENT_ID);
    }

    private static String getParameter(SavedRequest savedRequest, String parameterName) {
        var parameterValues = savedRequest.getParameterValues(parameterName);
        if (parameterValues.length != 1) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }
        return parameterValues[0];
    }
}
