package org.example.microservice.apigateway.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyExtractors;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.*;
import java.util.stream.Collectors;

@Component
public class KeycloakOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

    @Value("${security.keycloak.introspection-uri:http://localhost:8080/realms/your-realm/protocol/openid-connect/token/introspect}")
    private String introspectionUri;

    @Value("${security.keycloak.client-id:gateway}")
    private String clientId;

    @Value("${security.keycloak.client-secret:change-me}")
    private String clientSecret;

    private final WebClient webClient = WebClient.builder().build();

    @Override
    public OAuth2AuthenticatedPrincipal introspect(String token) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("token", token);
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);

        Map<String, Object> response = webClient.post()
                .uri(introspectionUri)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .bodyValue(form)
                .retrieve()
                .bodyToMono(Map.class)
                .blockOptional()
                .orElseThrow(() -> new IllegalArgumentException("Token introspection response empty"));

        Boolean active = (Boolean) response.getOrDefault(OAuth2TokenIntrospectionClaimNames.ACTIVE, Boolean.FALSE);
        if (active == null || !active) {
            throw new IllegalArgumentException("Token is not active");
        }

        // Extract subject
        String subject = Optional.ofNullable((String) response.get(OAuth2TokenIntrospectionClaimNames.SUBJECT))
                .orElse("anonymous");

        // Extract roles from realm_access or resource_access
        Set<String> roles = new HashSet<>();
        Object realmAccessObj = response.get("realm_access");
        if (realmAccessObj instanceof Map<?, ?> realmAccess) {
            Object realmRolesObj = realmAccess.get("roles");
            if (realmRolesObj instanceof Collection<?> c) {
                c.forEach(r -> roles.add(String.valueOf(r)));
            }
        }
        Object resourceAccessObj = response.get("resource_access");
        if (resourceAccessObj instanceof Map<?, ?> resAccess) {
            for (Object clientAccessObj : resAccess.values()) {
                if (clientAccessObj instanceof Map<?, ?> clientAccess) {
                    Object clientRolesObj = clientAccess.get("roles");
                    if (clientRolesObj instanceof Collection<?> c) {
                        c.forEach(r -> roles.add(String.valueOf(r)));
                    }
                }
            }
        }
        Collection<GrantedAuthority> authorities = roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toList());

        Map<String, Object> attributes = new HashMap<>(response);

        return new SimpleOAuth2AuthenticatedPrincipal(subject, attributes, authorities);
    }

    // Minimal principal implementation
    static class SimpleOAuth2AuthenticatedPrincipal implements OAuth2AuthenticatedPrincipal {
        private final String name;
        private final Map<String, Object> attributes;
        private final Collection<GrantedAuthority> authorities;

        SimpleOAuth2AuthenticatedPrincipal(String name,
                                           Map<String, Object> attributes,
                                           Collection<GrantedAuthority> authorities) {
            this.name = name;
            this.attributes = Collections.unmodifiableMap(new HashMap<>(attributes));
            this.authorities = Collections.unmodifiableCollection(new ArrayList<>(authorities));
        }

        @Override
        public Map<String, Object> getAttributes() {
            return attributes;
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return authorities;
        }

        @Override
        public String getName() {
            return name;
        }
    }
}

