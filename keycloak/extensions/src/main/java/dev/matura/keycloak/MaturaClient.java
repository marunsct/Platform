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
 * Calls maturad's {@code POST /internal/v1/token-context} (technical specification §6) and caches answers for a few
 * seconds, so a burst of token requests for the same user, app and tenant costs one call.
 */
public final class MaturaClient {

    /** What maturad answered: claims to add, or why no token may be issued. */
    public record Answer(Map<String, Object> claims, String refusal, String detail) {
        public boolean refused() { return refusal != null; }
    }

    /** What the mapper knows about the token being issued. */
    public record Request(String userId, String email, boolean emailVerified, String name, String locale,
                          String clientId, String tenant, String workspace) {
        String key() { return userId + "|" + clientId + "|" + tenant + "|" + workspace; }
    }

    private record Cached(Answer answer, long expiresAt) {}

    private static final ObjectMapper JSON = new ObjectMapper();

    private final URI endpoint;
    private final String token;
    private final HttpClient http;
    private final Duration ttl;
    private final Clock clock;
    private final Map<String, Cached> cache = new ConcurrentHashMap<>();

    public MaturaClient(String baseUrl, String token, Duration ttl, Clock clock) {
        this.endpoint = URI.create(baseUrl.replaceAll("/+$", "") + "/internal/v1/token-context");
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
        HttpRequest httpReq = HttpRequest.newBuilder(endpoint)
                .timeout(Duration.ofSeconds(3))
                .header("Authorization", "Bearer " + token)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(body)))
                .build();
        HttpResponse<String> res = http.send(httpReq, HttpResponse.BodyHandlers.ofString());
        Map<String, Object> out = res.body().isBlank() ? Map.of()
                : JSON.readValue(res.body(), new TypeReference<Map<String, Object>>() {});
        Answer answer;
        if (res.statusCode() == 200) {
            answer = new Answer(out, null, null);
        } else if (res.statusCode() == 403 && "access_denied".equals(out.get("error"))) {
            answer = new Answer(Map.of(), String.valueOf(out.get("error_description")), String.valueOf(out.get("detail")));
        } else {
            throw new IOException("maturad answered " + res.statusCode() + " for token context");
        }
        cache.put(req.key(), new Cached(answer, now + ttl.toMillis()));
        if (cache.size() > 10_000) {
            cache.entrySet().removeIf(e -> e.getValue().expiresAt() <= now);
        }
        return answer;
    }
}
