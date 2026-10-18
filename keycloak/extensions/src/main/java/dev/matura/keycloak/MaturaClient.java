package dev.matura.keycloak;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Calls maturad's internal API (technical specification §6): {@code POST /internal/v1/token-context}, whose answers
 * are cached for a few seconds so a burst of token requests for the same user, app and tenant costs one call, and the
 * sign-in checks {@code /internal/v1/mfa-policy} and {@code /internal/v1/sso-login}, which are not cached.
 */
public final class MaturaClient {

    /** What maturad answered: claims to add, or why no token may be issued. */
    public record Answer(Map<String, Object> claims, String refusal, String detail) {
        public boolean refused() { return refusal != null; }
    }

    /**
     * What the mapper knows about the token being issued. {@code audience} is what an agent's client asked a token
     * for (the {@code matura_app}, {@code audience} or {@code resource} parameter); maturad ignores it for apps.
     */
    public record Request(String userId, String email, boolean emailVerified, String name, String locale,
                          String clientId, String tenant, String workspace, long sessionStarted, long sessionLastUse,
                          String audience) {
        public Request(String userId, String email, boolean emailVerified, String name, String locale,
                       String clientId, String tenant, String workspace, long sessionStarted, long sessionLastUse) {
            this(userId, email, emailVerified, name, locale, clientId, tenant, workspace, sessionStarted, sessionLastUse,
                    null);
        }
        public Request(String userId, String email, boolean emailVerified, String name, String locale,
                       String clientId, String tenant, String workspace) {
            this(userId, email, emailVerified, name, locale, clientId, tenant, workspace, 0, 0, null);
        }
        String key() {
            return userId + "|" + clientId + "|" + tenant + "|" + workspace + "|" + sessionStarted + "|" + audience;
        }
    }

    private record Cached(Answer answer, long expiresAt) {}

    private static final ObjectMapper JSON = new ObjectMapper();

    private final String base;
    private final URI endpoint;
    private final String token;
    private final HttpClient http;
    private final Duration ttl;
    private final Clock clock;
    private final Map<String, Cached> cache = new ConcurrentHashMap<>();

    public MaturaClient(String baseUrl, String token, Duration ttl, Clock clock) {
        this.base = baseUrl.replaceAll("/+$", "");
        this.endpoint = URI.create(base + "/internal/v1/token-context");
        this.token = token;
        this.ttl = ttl;
        this.clock = clock;
        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
    }

    /** From MATURA_URL and MATURA_INTERNAL_TOKEN, with a 5-second cache. */
    public static MaturaClient fromEnv() {
        String url = System.getenv().getOrDefault("MATURA_URL", "http://maturad:8080");
        String token = System.getenv("MATURA_INTERNAL_TOKEN");
        if (token == null || token.isBlank()) {
            throw new IllegalStateException("MATURA_INTERNAL_TOKEN is not set for Keycloak");
        }
        return new MaturaClient(url, token, Duration.ofSeconds(5), Clock.systemUTC());
    }

    public Answer tokenContext(Request req) throws IOException, InterruptedException {
        long now = clock.millis();
        Cached hit = cache.get(req.key());
        if (hit != null && hit.expiresAt() > now) {
            return hit.answer();
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("user_id", req.userId());
        body.put("email", req.email() == null ? "" : req.email());
        body.put("email_verified", req.emailVerified());
        body.put("name", req.name() == null ? "" : req.name());
        body.put("locale", req.locale() == null ? "" : req.locale());
        body.put("client_id", req.clientId());
        body.put("tenant", req.tenant() == null ? "" : req.tenant());
        body.put("workspace", req.workspace() == null ? "" : req.workspace());
        body.put("session_started", req.sessionStarted());
        body.put("session_last_use", req.sessionLastUse());
        if (req.audience() != null && !req.audience().isBlank()) {
            body.put("audience", req.audience());
        }
        Answer answer = post(endpoint, body);
        cache.put(req.key(), new Cached(answer, now + ttl.toMillis()));
        if (cache.size() > 10_000) {
            cache.entrySet().removeIf(e -> e.getValue().expiresAt() <= now);
        }
        return answer;
    }

    /** Whether the user must sign in with a second factor (a tenant of theirs requires MFA). */
    public boolean mfaRequired(String userId) throws IOException, InterruptedException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("user_id", userId);
        Answer a = post(URI.create(base + "/internal/v1/mfa-policy"), body);
        if (a.refused()) {
            throw new IOException("maturad refused the MFA policy question: " + a.refusal());
        }
        return Boolean.TRUE.equals(a.claims().get("required"));
    }

    /**
     * Checks a sign-in through a tenant's identity provider; with a user id the user joins the tenant. A refusal
     * (address outside the tenant's verified domains, unknown provider…) comes back as a refused Answer.
     */
    public Answer ssoLogin(String alias, String email, String userId, String name) throws IOException, InterruptedException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("alias", alias);
        body.put("email", email == null ? "" : email);
        if (userId != null) {
            body.put("user_id", userId);
        }
        body.put("name", name == null ? "" : name);
        return post(URI.create(base + "/internal/v1/sso-login"), body);
    }

    private Answer post(URI uri, Map<String, Object> body) throws IOException, InterruptedException {
        HttpRequest httpReq = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(3))
                .header("Authorization", "Bearer " + token)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(body)))
                .build();
        HttpResponse<String> res = http.send(httpReq, HttpResponse.BodyHandlers.ofString());
        Map<String, Object> out = res.body().isBlank() ? Map.of()
                : JSON.readValue(res.body(), new TypeReference<Map<String, Object>>() {});
        if (res.statusCode() == 200) {
            return new Answer(out, null, null);
        }
        if (res.statusCode() == 403 && "access_denied".equals(out.get("error"))) {
            return new Answer(Map.of(), String.valueOf(out.get("error_description")), String.valueOf(out.get("detail")));
        }
        throw new IOException("maturad answered " + res.statusCode() + " for " + uri.getPath());
    }
}
