package com.bbende.saml.config;

import com.bbende.saml.api.AccessResource;
import com.bbende.saml.api.ProtectedResource;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.server.ServerProperties;
import org.glassfish.jersey.servlet.ServletProperties;
import org.springframework.context.annotation.Configuration;

import javax.ws.rs.ApplicationPath;

@Configuration
@ApplicationPath("/api")
public class JerseyResourceConfig extends ResourceConfig {

    public JerseyResourceConfig() {

        // register resources
        register(AccessResource.class);
        register(ProtectedResource.class);

        // include bean validation errors in response
        property(ServerProperties.BV_SEND_ERROR_IN_RESPONSE, true);

        // since we run Jersey as a filter, forward any 404s so requests continue on
        property(ServletProperties.FILTER_FORWARD_ON_404, true);
    }
}
