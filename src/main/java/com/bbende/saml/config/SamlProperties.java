package com.bbende.saml.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;

@ConstructorBinding
@ConfigurationProperties(prefix = "saml", ignoreUnknownFields = false)
public class SamlProperties {

    private final String clientId;
    private final String idpMetadataUrl;

    public SamlProperties(final String clientId, final String idpMetadataUrl) {
        this.clientId = clientId;
        this.idpMetadataUrl = idpMetadataUrl;
    }

    public String getClientId() {
        return clientId;
    }

    public String getIdpMetadataUrl() {
        return idpMetadataUrl;
    }

}
