package dev.matura.keycloak;

import org.keycloak.representations.AccessToken;

import java.util.List;
import java.util.Map;

/**
 * Copies maturad's token context into an access token (contract §2). {@code kind} is the subject's kind (human,
 * service or agent); {@code act} names the agent of a delegated token (RFC 8693 §4.1); {@code aud} from maturad is
 * the app an agent's token is for and is added to the token's audience.
 */
public final class MaturaClaims {

    static final List<String> NAMES = List.of("tid", "tenant", "wid", "troles", "roles", "perms", "perms_ref", "ver", "pmode", "kind", "act");

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
        if (claims.get("aud") instanceof String aud && !aud.isEmpty()) {
            token.addAudience(aud);
        }
    }
}
