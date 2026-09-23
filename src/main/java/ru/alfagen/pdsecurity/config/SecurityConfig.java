package ru.alfagen.pdsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Security filter chain. Public: the contract endpoint /process, liveness probes
 * and the demo page with its single endpoint. Closed: /api/** and actuator.
 * The API is stateless and cookie-free, so CSRF does not apply and its filter
 * ignores every request path.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) {
        try {
            http
                .csrf(csrf -> csrf.ignoringRequestMatchers("/**"))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/process", "/health", "/ready").permitAll()
                        // Demo page and its single endpoint: read-only showcase for reviewers.
                        .requestMatchers("/", "/index.html", "/demo/**").permitAll()
                        .requestMatchers("/api/**", "/actuator/**").denyAll()
                        .anyRequest().denyAll())
                .httpBasic(HttpBasicConfigurer::disable)
                .formLogin(FormLoginConfigurer::disable);
            return http.build();
        } catch (Exception e) {
            throw new IllegalStateException("security filter chain configuration failed", e);
        }
    }
}