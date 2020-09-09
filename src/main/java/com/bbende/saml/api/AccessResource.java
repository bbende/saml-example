package com.bbende.saml.api;

import com.bbende.saml.security.SamlService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import java.net.URI;
import java.util.UUID;

@Component
@Path("/access")
public class AccessResource {

    private static final Logger LOGGER = LoggerFactory.getLogger(AccessResource.class);

    /**
     * The name of the Cookie where we will store the SAML request identifier.
     */
    private static final String SAML_REQUEST_IDENTIFIER = "saml-request-identifier";

    @Context
    private UriInfo uriInfo;

    @Value("${security.authentication.cookie.name}")
    private String authenticationCookieName;

    private final SamlService samlService;

    public AccessResource(final SamlService samlService) {
        this.samlService = samlService;
    }

    // initiate a request to authenticate via SAML

    @GET
    @Consumes(MediaType.WILDCARD)
    @Produces(MediaType.WILDCARD)
    @Path("saml/request")
    public void samlRequest(@Context final HttpServletRequest servletRequest,
                            @Context final HttpServletResponse servletResponse) throws Exception {

        // generate an identifier to keep track of this request
        final String samlRequestIdentifier = UUID.randomUUID().toString();
        LOGGER.debug("Created SAML Request Identifier '{}'", new Object[]{samlRequestIdentifier});

        // generate a cookie to associate this login sequence
        setSamlRequestCookie(servletResponse, samlRequestIdentifier, 60);

        // initialize the state for this request
        final String state = samlService.createState(samlRequestIdentifier);

        // redirect to the idp
        final String callbackUrl = generateResourceUri("access", "saml", "callback");
        LOGGER.debug("Redirecting to identity provider with callback url '{}'", new Object[]{callbackUrl});
        samlService.redirectToIdentityProvider(servletResponse, callbackUrl, state);
    }

    // called by the IDP to process the SAML response

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_PLAIN)
    @Path("saml/callback")
    public Response samlCallback(@Context final HttpServletRequest httpServletRequest,
                                 @Context final HttpServletResponse httpServletResponse,
                                 @FormParam("SAMLResponse") final String samlResponseFormParam,
                                 @FormParam("RelayState") final String relayStateFormParam) throws Exception {

        // verify the request has the Cookie that was during the original request
        final String samlRequestIdentifier = getCookieValue(httpServletRequest.getCookies(), SAML_REQUEST_IDENTIFIER);
        if (samlRequestIdentifier == null) {
            final String identifierNotFoundMsg = "The login request identifier was not found in the request. Unable to continue.";
            LOGGER.error(identifierNotFoundMsg);
            return Response.status(Response.Status.BAD_REQUEST).entity(identifierNotFoundMsg).build();
        }

        // process the SAML response and extract the user identity
        final String callbackUrl = generateResourceUri("access", "saml", "callback");
        final String userIdentity = samlService.processSamlResponse(samlResponseFormParam, callbackUrl);
        LOGGER.debug("Processed SAML Response, user identity = '{}'", new Object[]{userIdentity});

        // verify the correct state was sent back
        if (relayStateFormParam == null || !samlService.isStateValid(samlRequestIdentifier, relayStateFormParam)) {
            LOGGER.error("The state value returned by the SAML identity provider does not match the stored state. Unable to continue login process.");

            // remove the SAML request cookie
            setSamlRequestCookie(httpServletResponse, null, 0);

            return Response.status(Response.Status.BAD_REQUEST)
                    .entity( "Purposed state does not match the stored state. Unable to continue login process.")
                    .build();
        }

        // NOTE: Normally in a real application we would create a JWT for the user, but to keep this example simple
        // we will create a Cookie and then check for it's presence in SimpleAuthenticationFilter
        setAuthenticationCookie(httpServletResponse, userIdentity, 300);

        return Response.ok("Successfully logged in as '" + userIdentity + "'").build();
    }

    @POST
    @Consumes(MediaType.WILDCARD)
    @Produces(MediaType.WILDCARD)
    @Path("saml/logout")
    public Response samlLogout(@Context final HttpServletRequest httpServletRequest,
                               @Context final HttpServletResponse httpServletResponse) throws Exception {

        // Remove our simple authentication Cookie
        setAuthenticationCookie(httpServletResponse, null, 0);

        return null;
    }

    // --- Helper methods

    private String generateResourceUri(final String... path) {
        URI uri = buildResourceUri(path);
        return uri.toString();
    }

    private URI buildResourceUri(final String... path) {
        final UriBuilder uriBuilder = uriInfo.getBaseUriBuilder();
        uriBuilder.segment(path);
        return uriBuilder.build();
    }

    private String getCookieValue(final Cookie[] cookies, final String name) {
        if (cookies != null) {
            for (final Cookie cookie : cookies) {
                if (name.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }

        return null;
    }

    private void setSamlRequestCookie(final HttpServletResponse httpServletResponse, final String value, int exp) {
        setCookie(httpServletResponse, SAML_REQUEST_IDENTIFIER, value, exp);
    }

    private void setAuthenticationCookie(final HttpServletResponse httpServletResponse, final String value, int exp) {
        setCookie(httpServletResponse,  authenticationCookieName, value, exp);
    }

    private void setCookie(HttpServletResponse httpServletResponse, String cookieName, String value, int exp) {
        final Cookie cookie = new Cookie(cookieName, value);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(exp);

        // NOTE: Normally we'd be doing SAML over an https connection and this would be enabled, but for
        // dev testing we disable this so the cookie will be set even when not running over https
        //cookie.setSecure(true);

        httpServletResponse.addCookie(cookie);
    }

}
