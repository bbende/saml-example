package com.bbende.saml.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;

public class SimpleAuthenticationToken extends AbstractAuthenticationToken {

    private final SimpleUserDetails simpleUserDetails;

    public SimpleAuthenticationToken(final SimpleUserDetails simpleUserDetails) {
        super(simpleUserDetails.getAuthorities());
        this.simpleUserDetails = simpleUserDetails;
    }

    @Override
    public Object getCredentials() {
        return simpleUserDetails.getPassword();
    }

    @Override
    public Object getPrincipal() {
        return simpleUserDetails;
    }
}
