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

    volatile String mfaAnswer = "{\"required\":true,\"tenants\":[\"acme\"]}";
    volatile int ssoStatus = 200;
    volatile String ssoAnswer = "{\"tid\":\"x\",\"tenant\":\"acme\",\"joined\":true}";

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
        server.createContext("/internal/v1/mfa-policy", ex -> {
            lastBody.set(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] b = mfaAnswer.getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
        server.createContext("/internal/v1/sso-login", ex -> {
            lastBody.set(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] b = ssoAnswer.getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(ssoStatus, b.length);
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

    @Test
    void mfaPolicy() throws Exception {
        assertTrue(client().mfaRequired("u1"));
        assertTrue(lastBody.get().contains("\"user_id\":\"u1\""));
        mfaAnswer = "{\"required\":false,\"tenants\":[]}";
        assertFalse(client().mfaRequired("u1"));
    }

    @Test
    void ssoLogin() throws Exception {
        MaturaClient.Answer a = client().ssoLogin("t-acme", "ana@acme.test", "u1", "Ana");
        assertFalse(a.refused());
        assertEquals(true, a.claims().get("joined"));
        assertTrue(lastBody.get().contains("\"alias\":\"t-acme\""));

        ssoStatus = 403;
        ssoAnswer = "{\"error\":\"access_denied\",\"error_description\":\"domain_not_verified\",\"detail\":\"no\"}";
        a = client().ssoLogin("t-acme", "ceo@globex.test", null, null);
        assertTrue(a.refused());
        assertEquals("domain_not_verified", a.refusal());
        assertFalse(lastBody.get().contains("user_id"), "no user id before the account exists");
    }

    @Test
    void sessionTimesAreSent() throws Exception {
        client().tokenContext(new MaturaClient.Request("u", null, true, null, null, "agentcanvas", "acme", null,
                1700000000000L, 1700000060000L));
        assertTrue(lastBody.get().contains("\"session_started\":1700000000000"));
        assertTrue(lastBody.get().contains("\"session_last_use\":1700000060000"));
    }
}
