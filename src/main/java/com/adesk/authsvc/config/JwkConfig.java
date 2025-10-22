package com.adesk.authsvc.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
public class JwkConfig {

    @Value("${app.jwk.key-id}")
    String keyId;

    @Bean
    public JWKSource<SecurityContext> jwkSource() throws Exception {
        RSAKey rsa = new RSAKeyGenerator(2048).keyID(keyId).generate();
        JWKSet jwkSet = new JWKSet(rsa);
        return new ImmutableJWKSet<>(jwkSet);
    }
}
