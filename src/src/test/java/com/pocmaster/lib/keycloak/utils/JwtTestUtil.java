package com.pocmaster.lib.keycloak.utils;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class JwtTestUtil {

    public static Jwt createJwt(String preferredUsername, List<String> roles) {

        Map<String, Object> claims = new HashMap<>();
        claims.put(JwtClaimNames.SUB, "defaultUser");
        if(preferredUsername != null){
            claims.put("preferred_username", preferredUsername);
        }
        claims.put("realm_access", Map.of("pocmaster-roles", roles));
        claims.put("pocmaster-roles", roles);

        Map<String, Object> headers = new HashMap<>();
        headers.put("alg", "none");

        // Création du JWT
        return new Jwt(
                "token-value",
                Instant.now(),
                Instant.now().plusSeconds(3600),
                headers,
                claims
        );
    }
}
