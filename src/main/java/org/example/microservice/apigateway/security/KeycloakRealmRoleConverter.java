package org.example.microservice.apigateway.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class KeycloakRealmRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Set<String> roles = new HashSet<>();

        // Prefer realm_access roles
        Map<String, Object> realmAccess = jwt.getClaim("realm_access");
        if (realmAccess != null) {
            Object realmRolesObj = realmAccess.get("roles");
            if (realmRolesObj instanceof Collection<?>) {
                ((Collection<?>) realmRolesObj).forEach(r -> roles.add(String.valueOf(r)));
            }
        }

        // Fallback to resource_access roles for this client (if needed)
        Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
        if (resourceAccess != null) {
            for (Object clientAccessObj : resourceAccess.values()) {
                if (clientAccessObj instanceof Map<?, ?> clientAccess) {
                    Object clientRolesObj = clientAccess.get("roles");
                    if (clientRolesObj instanceof Collection<?>) {
                        ((Collection<?>) clientRolesObj).forEach(r -> roles.add(String.valueOf(r)));
                    }
                }
            }
        }

        if (roles.isEmpty()) {
            return Collections.emptyList();
        }

        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toList());
    }
}

