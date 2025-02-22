package com.pocmaster.lib.keycloak.config;


import com.pocmaster.lib.keycloak.config.properties.JwtAuthProperties;
import com.pocmaster.lib.keycloak.config.properties.KeycloakClientConfigProperties;
import com.pocmaster.lib.keycloak.service.jwt.JwtAuthConverter;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
@EnableConfigurationProperties({JwtAuthProperties.class, KeycloakClientConfigProperties.class})
public class KeycloakAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public JwtAuthConverter jwtAuthConverter(JwtAuthProperties properties) {
        return new JwtAuthConverter(properties);
    }
}
