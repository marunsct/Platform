package dev.matura.keycloak;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.AccessToken;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class MaturaClientTest {

    HttpServer server;
    AtomicInteger calls = new AtomicInteger();
    AtomicReference<String> lastAuth = new AtomicReference<>();
    AtomicReference<String> lastBody = new AtomicReference<>();
    volatile int status = 200;
    volatile String answer = """
            {"tid":"0192b7a4-6000-7000-8000-000000000001","tenant":"acme","wid":"0192b7a4-6001-7000-8000-000000000001",
             "troles":["member"],"roles":["editor"],"perms":["run.start","workflow.read"],"ver":{"u":12,"m":40,"t":7},
             "pmode":"shared"}""";

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/internal/v1/token-context", ex -> {
            calls.incrementAndGet();
            lastAuth.set(ex.getRequestHeaders().getFirst("Authorization"));
            lastBody.set(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] b = answer.getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(status, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
        server.start();
    }

    @AfterEach
    void stop() { server.stop(0); }

    MaturaClient client() {
        return new MaturaClient("http://127.0.0.1:" + server.getAddress().getPort() + "/", "secret-token",
                Duration.ofSeconds(5), Clock.systemUTC());
    }

    MaturaClient.Request req(String tenant) {
        return new MaturaClient.Request("0192b7a4-5c1e-7d2a-9f00-4b1e2a9c0d11", "ana@acme.test", true, "Ana",
                null, "agentcanvas", tenant, null);
    }

    @Test
    void addsClaimsAndCaches() throws Exception {
        MaturaClient c = client();
        MaturaClient.Answer a = c.tokenContext(req("acme"));
        assertFalse(a.refused());
        assertEquals("Bearer secret-token", lastAuth.get());
        assertTrue(lastBody.get().contains("\"client_id\":\"agentcanvas\""));
        assertTrue(lastBody.get().contains("\"tenant\":\"acme\""));

        AccessToken token = new AccessToken();
        token.getOtherClaims().put("perms_ref", "stale");
        MaturaClaims.apply(token, a.claims());
        Map<String, Object> claims = token.getOtherClaims();
        assertEquals("acme", claims.get("tenant"));
        assertEquals(List.of("run.start", "workflow.read"), claims.get("perms"));
        assertEquals("shared", claims.get("pmode"));
        assertFalse(claims.containsKey("perms_ref"), "stale claims are removed");

        c.tokenContext(req("acme"));
        assertEquals(1, calls.get(), "second request within the TTL is cached");
        c.tokenContext(req("globex"));
        assertEquals(2, calls.get(), "another tenant is another key");
    }

    @Test
    void refusalIsReported() throws Exception {
        status = 403;
        answer = "{\"error\":\"access_denied\",\"error_description\":\"app_not_enabled\",\"detail\":\"not enabled\"}";
        MaturaClient.Answer a = client().tokenContext(req("acme"));
        assertTrue(a.refused());
        assertEquals("app_not_enabled", a.refusal());
    }

    @Test
    void serverErrorsThrow() {
        status = 500;
        answer = "{}";
        assertThrows(IOException.class, () -> client().tokenContext(req("acme")));
    }
}
