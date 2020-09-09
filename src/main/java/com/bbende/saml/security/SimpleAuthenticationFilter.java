package com.bbende.saml.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * A simple authentication filter that looks for a cookie in the incoming request with a given name.
 *
 * If the cookie exists, then an authenticated user it set in the context using the cookie value as the user identity.
 *
 * This is simply for demo/testing purposes so that after doing a SAML login, we can have an authenticated user to logout.
 */
public class SimpleAuthenticationFilter extends GenericFilterBean {

    private static final Logger LOGGER = LoggerFactory.getLogger(SimpleAuthenticationFilter.class);

    private final String authenticationCookieName;

    public SimpleAuthenticationFilter(final String authenticationCookieName) {
        this.authenticationCookieName = authenticationCookieName;
    }

    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain)
            throws IOException, ServletException {
        LOGGER.debug("Checking for authentication Cookie with name '{}'", new Object[]{authenticationCookieName});

        final String authenticatedUserIdentity = getCookieValue((HttpServletRequest) request, authenticationCookieName);
        if (authenticatedUserIdentity != null) {
            final SimpleUserDetails userDetails = new SimpleUserDetails(authenticatedUserIdentity);
            final Authentication authentication = new SimpleAuthenticationToken(userDetails);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            LOGGER.debug("Found authenticated user from Cookie: {}", new Object[]{authenticatedUserIdentity});
        } else {
            LOGGER.debug("Authentication cookie was not found");
        }

        chain.doFilter(request, response);
    }

    private String getCookieValue(final HttpServletRequest request, final String cookieName) {
        String value = null;

        final Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookieName.equals(cookie.getName())) {
                    value = cookie.getValue();
                    break;
                }
            }
        }

        return value;
    }
}
