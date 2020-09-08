/*
 * (c) 2018-2020 Cloudera, Inc. All rights reserved.
 *
 *   This code is provided to you pursuant to your written agreement with Cloudera, which may be the terms of the
 *  Affero General Public License version 3 (AGPLv3), or pursuant to a written agreement with a third party authorized
 *  to distribute this code.  If you do not have a written agreement with Cloudera or with an authorized and
 *  properly licensed third party, you do not have any rights to this code.
 *
 *   If this code is provided to you under the terms of the AGPLv3:
 *   (A) CLOUDERA PROVIDES THIS CODE TO YOU WITHOUT WARRANTIES OF ANY KIND;
 *   (B) CLOUDERA DISCLAIMS ANY AND ALL EXPRESS AND IMPLIED WARRANTIES WITH RESPECT TO THIS CODE, INCLUDING BUT NOT
 *       LIMITED TO IMPLIED WARRANTIES OF TITLE, NON-INFRINGEMENT, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE;
 *   (C) CLOUDERA IS NOT LIABLE TO YOU, AND WILL NOT DEFEND, INDEMNIFY, OR HOLD YOU HARMLESS FOR ANY CLAIMS ARISING
 *       FROM OR RELATED TO THE CODE; AND
 *   (D) WITH RESPECT TO YOUR EXERCISE OF ANY RIGHTS GRANTED TO YOU FOR THE CODE, CLOUDERA IS NOT LIABLE FOR ANY
 *       DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, PUNITIVE OR CONSEQUENTIAL DAMAGES INCLUDING, BUT NOT LIMITED
 *       TO, DAMAGES RELATED TO LOST REVENUE, LOST PROFITS, LOSS OF INCOME, LOSS OF BUSINESS ADVANTAGE OR
 *       UNAVAILABILITY, OR LOSS OR CORRUPTION OF DATA.
 *
 */
package com.bbende.saml.service;

import com.bbende.saml.config.SamlProperties;
import com.coveo.saml.SamlClient;
import com.coveo.saml.SamlResponse;
import org.jvnet.hk2.internal.CacheKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.HttpMethod;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.math.BigInteger;
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
    public void redirectToIdentityProvider(final HttpServletResponse response, final String callbackUrl,
                                           final String relayState) throws Exception {
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

    private synchronized SamlClient getSamlClient(final String callbackUrl) throws Exception {
        SamlClient samlClient = samlClientLookup.get(callbackUrl);

        if (samlClient == null) {
            final String clientId = samlProperties.getClientId();
            final URL idpMetadataUrl = new URL(samlProperties.getIdpMetadataUrl());
            LOGGER.debug("Creating new SamlClient for callback url '{}'", new Object[]{callbackUrl});

            try (final InputStream idpMetadataIn = idpMetadataUrl.openStream();
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
