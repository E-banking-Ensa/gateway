package org.example.microservice.apigateway.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // Disable CSRF for stateless APIs
        http.csrf(csrf -> csrf.disable());

        // Authorize requests based on path and roles
        http.authorizeHttpRequests(auth -> auth
                // Public: allow unauthenticated access to auth endpoints (login, callbacks) and actuator health/info
                .requestMatchers("/api/auth/**", "/actuator/health", "/actuator/info").permitAll()
                // Management gateway endpoint can be restricted to Admin
                .requestMatchers("/actuator/**").hasRole("Admin")
                // User-related routes (example roles: Client, Admin)
                .requestMatchers("/api/users/**", "/api/accounts/**", "/api/payments/**").hasAnyRole("Client", "Admin")
                // Agent-focused routes
                .requestMatchers("/api/legacy/**", "/api/ai-assistant/**").hasAnyRole("Agent", "Admin")
                // Crypto routes could be Admin and Agent for now
                .requestMatchers("/api/crypto/**").hasAnyRole("Agent", "Admin")
                // Everything else requires authentication
                .anyRequest().authenticated()
        );

        // Configure resource server to use opaque token introspection via Keycloak API
        http.oauth2ResourceServer(oauth2 -> oauth2
                .opaqueToken(ot -> ot.introspector(keycloakOpaqueTokenIntrospectorBean()))
        );

        // Disable default login form, use bearer tokens only
        http.httpBasic(Customizer.withDefaults());

        return http.build();
    }

    // Renamed bean factory method to avoid bean name collision with any precompiled class-level bean
    @Bean("keycloakOpaqueTokenIntrospectorBean")
    public OpaqueTokenIntrospector keycloakOpaqueTokenIntrospectorBean() {
        return new KeycloakOpaqueTokenIntrospector();
    }
}
