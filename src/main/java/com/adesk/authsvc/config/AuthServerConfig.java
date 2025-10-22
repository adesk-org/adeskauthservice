package com.adesk.authsvc.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

@Configuration
public class AuthServerConfig {

    @Value("${app.issuer}")
    String issuer;

    @Value("${app.oauth.authorize-endpoint:/oauth/authorize}")
    String authorizeEndpoint;

    @Value("${app.oauth.token-endpoint:/oauth/token}")
    String tokenEndpoint;

    @Value("${app.oauth.jwk-set-endpoint:/.well-known/jwks.json}")
    String jwkEndpoint;

    @Value("${app.oauth.introspection-endpoint:/oauth/introspect}")
    String introspectionEndpoint;

    @Value("${app.oauth.revocation-endpoint:/oauth/revoke}")
    String revocationEndpoint;

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        // Map SAS default /oauth2/* endpoints to your /oauth/* and well-known paths
        return AuthorizationServerSettings.builder().issuer(issuer)
                .authorizationEndpoint(authorizeEndpoint).tokenEndpoint(tokenEndpoint)
                .jwkSetEndpoint(jwkEndpoint).tokenIntrospectionEndpoint(introspectionEndpoint)
                .tokenRevocationEndpoint(revocationEndpoint).oidcUserInfoEndpoint("/userinfo")
                .oidcClientRegistrationEndpoint("/connect/register") // not in your spec; harmless
                .build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(AppClientProperties props) {
        InMemoryRegisteredClientRepository repo =
                new InMemoryRegisteredClientRepository(props.toRegisteredClients());
        return repo;
    }

    @Bean
    public OAuth2AuthorizationService authorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }

    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService() {
        return new InMemoryOAuth2AuthorizationConsentService();
    }
}
