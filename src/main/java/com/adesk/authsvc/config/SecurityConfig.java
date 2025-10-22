package com.adesk.authsvc.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.web.SecurityFilterChain;

import com.adesk.authsvc.user.UserStore;

@Configuration
public class SecurityConfig {

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // Users
    @Bean
    public UserDetailsService userDetailsService(UserStore store) {
        return username -> store.load(username)
                .orElseThrow(() -> new UsernameNotFoundException("not found"));
    }

    /** Security for the OAuth2 Authorization Server endpoints */
    @Bean
    @Order(1)
    SecurityFilterChain asSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        return http.build();
    }

    /** Security for our REST endpoints (/v1/**, /.well-known/**) */
    @Bean
    @Order(2)
    SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/.well-known/**", "/v1/auth/register", "/v1/auth/login")
                .permitAll().anyRequest().authenticated())
                .oauth2ResourceServer(oauth -> oauth.jwt(Customizer.withDefaults()))
                .formLogin(Customizer.withDefaults()) // simple login page for /oauth/authorize
                .csrf(csrf -> csrf.ignoringRequestMatchers("/v1/auth/**", "/oauth/token",
                        "/oauth/revoke", "/oauth/introspect"));
        return http.build();
    }
}
