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
                    .clientId(c.clientId).redirectUris(uris -> uris.addAll(c.redirectUris))
                    .scope("openid").scope("profile").scope("email");
            c.scopes.forEach(b::scope);
            if (Boolean.TRUE.equals(c.confidential)) {
                b.clientSecret(
                        c.clientSecret != null ? pe.encode(c.clientSecret) : pe.encode("change-me"))
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
        public String clientId;
        public String clientSecret;
        public List<String> redirectUris = new ArrayList<>();
        public List<String> scopes = new ArrayList<>();
        public Boolean confidential = false;
    }
}
