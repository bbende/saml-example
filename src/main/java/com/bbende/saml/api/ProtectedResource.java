package com.bbende.saml.api;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Component
@Path("/protected")
public class ProtectedResource {

    @GET
    @Consumes(MediaType.WILDCARD)
    @Produces(MediaType.TEXT_PLAIN)
    public Response getProtectedResource() {
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        final String currentUser = authentication.getName();
        return Response.ok("PROTECTED RESOURCE - The current user is `" + currentUser + "'").build();
    }

}
