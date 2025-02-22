package com.pocmaster.lib.keycloak.service.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.pocmaster.lib.keycloak.config.properties.JwtAuthProperties;
import com.pocmaster.lib.keycloak.utils.JwtTestUtil;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Collection;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
public class JwtAuthConverterTest {

    @Mock
    private JwtAuthProperties jwtAuthProperties;

    @InjectMocks
    private JwtAuthConverter jwtAuthConverter;

    @SneakyThrows
    @BeforeEach
    public void setUp() {
        String jsonConfig = """
            {
                "principleAttribute": "preferred_username",
                "resourceRoles": "pocmaster-roles"
            }
            """;
        ObjectMapper objectMapper = new JsonMapper();

        jwtAuthProperties =  objectMapper.readValue(jsonConfig, JwtAuthProperties.class);
        jwtAuthConverter = new JwtAuthConverter(jwtAuthProperties);
    }

    @Test
    public void testConvert_WithRolesAndPrincipalClaim() {
        Jwt jwt = JwtTestUtil.createJwt("user123", List.of("user", "admin"));

        JwtAuthenticationToken authenticationToken = (JwtAuthenticationToken) jwtAuthConverter.convert(jwt);

        assertEquals("user123", authenticationToken.getName());
        Collection<? extends GrantedAuthority> authorities = authenticationToken.getAuthorities();
        assertEquals(2, authorities.size());
        assertTrue(authorities.contains(new SimpleGrantedAuthority("ROLE_user")));
        assertTrue(authorities.contains(new SimpleGrantedAuthority("ROLE_admin")));
    }

    @Test
    public void testConvert_WithNoRoles() {
        Jwt jwt = JwtTestUtil.createJwt("user123", List.of());
        JwtAuthenticationToken authenticationToken = (JwtAuthenticationToken) jwtAuthConverter.convert(jwt);

        assertEquals("user123", authenticationToken.getName());
        assertTrue(authenticationToken.getAuthorities().isEmpty());
    }

    @SneakyThrows
    @Test
    public void testConvert_WithDefaultPrincipalClaim() {

        String jsonConfig = """
            {
                "resourceRoles": "pocmaster-roles"
            }
            """;
        ObjectMapper objectMapper = new JsonMapper();

        jwtAuthProperties =  objectMapper.readValue(jsonConfig, JwtAuthProperties.class);
        jwtAuthConverter = new JwtAuthConverter(jwtAuthProperties);

        Jwt jwt = JwtTestUtil.createJwt(null, List.of("user"));
        JwtAuthenticationToken authenticationToken = (JwtAuthenticationToken) jwtAuthConverter.convert(jwt);

        assertEquals("defaultUser", authenticationToken.getName());
        assertEquals(1, authenticationToken.getAuthorities().size());
        assertTrue(authenticationToken.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_user")));
    }
}