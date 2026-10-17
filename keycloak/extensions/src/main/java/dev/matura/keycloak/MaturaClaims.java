package dev.matura.keycloak;

import org.keycloak.representations.AccessToken;

import java.util.List;
import java.util.Map;

/** Copies maturad's token context into an access token (contract §2). */
public final class MaturaClaims {

    static final List<String> NAMES = List.of("tid", "tenant", "wid", "troles", "roles", "perms", "perms_ref", "ver", "pmode");

    private MaturaClaims() {}

    public static void apply(AccessToken token, Map<String, Object> claims) {
        for (String name : NAMES) {
            Object v = claims.get(name);
            if (v == null || (v instanceof String s && s.isEmpty())) {
                token.getOtherClaims().remove(name);
            } else {
                token.getOtherClaims().put(name, v);
            }
        }
    }
}
