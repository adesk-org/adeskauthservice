package com.adesk.authsvc.config;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

@Configuration
@ConfigurationProperties(prefix = "app")
public class AppClientProperties {

    private List<Client> clients = new ArrayList<>();

    public List<Client> getClients() {
        return clients;
    }

    public void setClients(List<Client> clients) {
        this.clients = clients;
    }

    public List<RegisteredClient> toRegisteredClients() {
        PasswordEncoder pe = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        List<RegisteredClient> list = new ArrayList<>();
        for (Client c : clients) {
            RegisteredClient.Builder b = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId(c.getClientId()).redirectUris(uris -> uris.addAll(c.getRedirectUris()))
                    .scope("openid").scope("profile").scope("email");
            c.getScopes().forEach(b::scope);
            if (Boolean.TRUE.equals(c.getConfidential())) {
                b.clientSecret(c.getClientSecret() != null ? pe.encode(c.getClientSecret())
                        : pe.encode("change-me"))
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
            } else {
                b.clientAuthenticationMethod(ClientAuthenticationMethod.NONE);
            }
            b.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
            list.add(b.build());
        }
        return list;
    }

    public static class Client {
        private String clientId;
        private String clientSecret;
        private List<String> redirectUris = new ArrayList<>();
        private List<String> scopes = new ArrayList<>();
        private Boolean confidential = Boolean.FALSE;

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public List<String> getRedirectUris() {
            return redirectUris;
        }

        public void setRedirectUris(List<String> redirectUris) {
            this.redirectUris = redirectUris != null ? new ArrayList<>(redirectUris)
                    : new ArrayList<>();
        }

        public List<String> getScopes() {
            return scopes;
        }

        public void setScopes(List<String> scopes) {
            this.scopes = scopes != null ? new ArrayList<>(scopes) : new ArrayList<>();
        }

        public Boolean getConfidential() {
            return confidential;
        }

        public void setConfidential(Boolean confidential) {
            this.confidential = confidential;
        }
    }
}
