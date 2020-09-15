package com.bbende.saml.security;

import com.bbende.saml.config.SamlProperties;
import com.coveo.saml.BrowserUtils;
import com.coveo.saml.SamlClient;
import com.coveo.saml.SamlResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.HttpMethod;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.math.BigInteger;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

/**
 * Wrapper around the saml-client library.
 */
@Service
public class SamlService {

    private static final Logger LOGGER = LoggerFactory.getLogger(SamlService.class);

    /**
     * SAML properties from application.properties.
     */
    private final SamlProperties samlProperties;

    /**
     * Lookup from callback url to the SamlClient for the given callback url.
     */
    private final Map<String,SamlClient> samlClientLookup;

    /**
     * Lookup from request identifier to state value.
     */
    private final Map<String,String> stateLookup;

    public SamlService(final SamlProperties samlProperties) {
        this.samlProperties = samlProperties;
        this.samlClientLookup = new HashMap<>();
        this.stateLookup = new HashMap<>();
    }

    /**
     * Creates a state value for the given request identifier and caches it for later retrieval.
     *
     * @param samlRequestIdentifier the request identifier
     * @return the state value for the given identifier
     */
    public String createState(final String samlRequestIdentifier) {
        final String stateValue = generateStateValue();

        synchronized (stateLookup) {
            final String cachedState = stateLookup.computeIfAbsent(samlRequestIdentifier, (k) -> stateValue);
            if (!timeConstantEqualityCheck(stateValue, cachedState)) {
                throw new IllegalStateException("An existing login request is already in progress.");
            }
        }

        return stateValue;
    }

    /**
     * Determines if the proposed state for the given request matches the cached state for the given request.
     *
     * @param samlRequestIdentifier the request identifier
     * @param proposedState the proposed state
     * @return true if proposed state matches cached state, false otherwise
     */
    public boolean isStateValid(final String samlRequestIdentifier, final String proposedState) {
        if (proposedState == null) {
            throw new IllegalArgumentException("Proposed state must be specified.");
        }

        synchronized (stateLookup) {
            final String cachedState = stateLookup.get(samlRequestIdentifier);
            if (cachedState != null) {
                stateLookup.remove(samlRequestIdentifier);
            }

            return cachedState != null && timeConstantEqualityCheck(cachedState, proposedState);
        }
    }

    /**
     * Redirects to the identity provider.
     *
     * @param response the response to redirect
     * @param callbackUrl the callback url to pass to the idp
     * @param relayState the state value to relay to the idp
     * @throws Exception if an error occurs creating a SamlClient
     */
    public void sendLoginRequest(final HttpServletResponse response, final String callbackUrl, final String relayState)
            throws Exception {
        final SamlClient samlClient = getSamlClient(callbackUrl);
        samlClient.redirectToIdentityProvider(response, relayState);
    }

    /**
     * Processes the encoded SAML response.
     *
     * @param encodedSamlResponse the value of the form-field 'SAMLResponse'
     * @param callbackUrl the callback url which was used to create the original request
     * @return the identity of the user from the SAML response
     * @throws Exception if an error occurs processing the SAML response
     */
    public String processSamlResponse(final String encodedSamlResponse, final String callbackUrl) throws Exception {
        final SamlClient samlClient = samlClientLookup.get(callbackUrl);
        if (samlClient == null) {
            throw new IllegalStateException("SAML Client does not exist for given callback url: " + callbackUrl);
        }

        final SamlResponse samlResponse = samlClient.decodeAndValidateSamlResponse(encodedSamlResponse, HttpMethod.POST);
        return samlResponse.getNameID();
    }

    public void sendLogoutRequest(final HttpServletResponse response, final String userIdentity,
                                  final String callbackUrl, final String relayState) throws Exception {

        final String singleLogoutUrl = "https://idp.ssocircle.com:443/sso/IDPSloPost/metaAlias/publicidp";

        final SamlClient samlClient = getSamlClient(callbackUrl);
        final String logoutRequest = samlClient.getLogoutRequest(userIdentity);

        Map<String, String> values = new HashMap<>();
        values.put("SAMLRequest", logoutRequest);
        if (relayState != null) {
            values.put("RelayState", relayState);
        }

        BrowserUtils.postUsingBrowser(singleLogoutUrl, response, values);

        //samlClient.redirectToIdentityProvider(response, relayState, userIdentity);
    }

    private synchronized SamlClient getSamlClient(final String callbackUrl) throws Exception {
        SamlClient samlClient = samlClientLookup.get(callbackUrl);

        if (samlClient == null) {
            LOGGER.debug("Creating new SamlClient for callback url '{}'", new Object[]{callbackUrl});

            final String clientId = samlProperties.getClientId();
            LOGGER.debug("Client id is '{}'", new Object[]{samlProperties.getClientId()});

            final URI idpMetadataUrl = new URI(samlProperties.getIdpMetadataUrl());
            LOGGER.debug("IDP Metadata URL is '{}'", new Object[]{samlProperties.getIdpMetadataUrl()});

            try (final InputStream idpMetadataIn = idpMetadataUrl.toURL().openStream();
                 final Reader ipdMetadataReader = new InputStreamReader(idpMetadataIn)) {
                samlClient = SamlClient.fromMetadata(clientId, callbackUrl, ipdMetadataReader);
                samlClientLookup.put(callbackUrl, samlClient);
            }
        }

        return samlClient;
    }

    private String generateStateValue() {
        return new BigInteger(130, new SecureRandom()).toString(32);
    }

    private boolean timeConstantEqualityCheck(final String value1, final String value2) {
        if (value1 == null || value2 == null) {
            return false;
        }

        return MessageDigest.isEqual(value1.getBytes(StandardCharsets.UTF_8), value2.getBytes(StandardCharsets.UTF_8));
    }

}
