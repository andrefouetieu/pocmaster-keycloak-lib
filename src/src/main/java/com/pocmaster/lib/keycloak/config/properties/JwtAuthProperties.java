package com.pocmaster.lib.keycloak.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "jwt.auth.converter")
public record JwtAuthProperties(String principleAttribute, String resourceRoles) {
}
