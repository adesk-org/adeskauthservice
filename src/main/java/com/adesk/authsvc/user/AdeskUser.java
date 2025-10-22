package com.adesk.authsvc.user;

import java.util.List;

public record AdeskUser(String username, String passwordHash, String displayName, String tenantId,
        List<String> roles, List<String> teams) {
}
