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
 * Security filter chain. Only /process and liveness are public; /api/**, /demo/**
 * and actuator are closed. API is stateless and cookie-free, therefore CSRF is
 * not applicable and its filter simply ignores every request path.
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
                        .requestMatchers("/api/**", "/demo/**", "/actuator/**").denyAll()
                        .anyRequest().denyAll())
                .httpBasic(HttpBasicConfigurer::disable)
                .formLogin(FormLoginConfigurer::disable);
            return http.build();
        } catch (Exception e) {
            throw new IllegalStateException("security filter chain configuration failed", e);
        }
    }
}