package com.adesk.authsvc.user;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class UserStore {

    private final Map<String, AdeskUser> users = new HashMap<>();
    private final PasswordEncoder pe;

    public UserStore(PasswordEncoder pe) {
        this.pe = pe;
        // seed demo user
        save("agent@acme.com", "password-12+", "Acme Agent", "tenant-acme", List.of("AGENT"),
                List.of("Support"));
    }

    public Optional<UserDetails> load(String username) {
        AdeskUser u = users.get(username);
        if (u == null)
            return Optional.empty();
        return Optional.of(User.withUsername(u.username()).password(u.passwordHash())
                .authorities(u.roles().toArray(String[]::new)).build());
    }

    public Optional<AdeskUser> find(String username) {
        return Optional.ofNullable(users.get(username));
    }

    public void save(String email, String rawPassword, String displayName, String tenantId,
            List<String> roles, List<String> teams) {
        users.put(email,
                new AdeskUser(email, pe.encode(rawPassword), displayName, tenantId, roles, teams));
    }
}
