package com.adesk.authsvc.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import com.adesk.authsvc.user.AdeskUser;
import com.adesk.authsvc.user.UserStore;

@Configuration
public class TokenCustomizer {

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> adeskClaims(UserStore store) {
        return context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())
                    || OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
                String sub = context.getPrincipal().getName();
                AdeskUser u = store.find(sub).orElse(null);
                if (u != null) {
                    context.getClaims().claims(claims -> {
                        claims.put("tenant_id", u.tenantId());
                        claims.put("roles", u.roles());
                        claims.put("teams", u.teams());
                    });
                }
            }
        };
    }
}
