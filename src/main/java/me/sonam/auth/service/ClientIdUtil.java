package me.sonam.auth.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

public class ClientIdUtil {
    private static final Logger LOG = LoggerFactory.getLogger(ClientIdUtil.class);

    public static String getClientId(RequestCache requestCache) {
        var requestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        var request = requestAttributes.getRequest();
        var response = requestAttributes.getResponse();
        var savedRequest = requestCache.getRequest(request, response);
        return ClientIdUtil.getParameter(savedRequest, OAuth2ParameterNames.CLIENT_ID);
    }

    private static String getParameter(SavedRequest savedRequest, String parameterName) {
        if (savedRequest == null) {
            return "";
        }
        var parameterValues = savedRequest.getParameterValues(parameterName);
        if (parameterValues.length != 1) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }
        return parameterValues[0];
    }
}
