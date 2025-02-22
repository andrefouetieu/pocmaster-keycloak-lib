package com.pocmaster.lib.keycloak.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "api.keycloak")
public record KeycloakClientConfigProperties(
        String baseurl,
        String realm,
        String username,
        String password,
        String clientId,
        String clientSecret
) {
}
