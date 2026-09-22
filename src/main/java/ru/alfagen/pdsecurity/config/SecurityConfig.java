package ru.alfagen.pdsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Security filter chain. Only /process and liveness are public; /api/**, /demo/**
 * and actuator are closed. CSRF is disabled so POST JSON is not blocked.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/process", "/health", "/ready").permitAll()
                        .requestMatchers("/api/**", "/demo/**", "/actuator/**").denyAll()
                        .anyRequest().denyAll())
                .httpBasic(basic -> basic.disable())
                .formLogin(form -> form.disable());
        return http.build();
    }
}