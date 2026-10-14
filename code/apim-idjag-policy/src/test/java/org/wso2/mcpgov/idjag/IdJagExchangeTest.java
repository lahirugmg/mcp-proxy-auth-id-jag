package org.wso2.mcpgov.idjag;

import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Steps 1 and 2 against fake token endpoints for the IdP (/idp/token) and the resource's
 * authorization server (/as/token). The live counterpart is {@link LiveChainTest}.
 */
class IdJagExchangeTest {

    static final String AUDIENCE = "http://localhost:9500";
    static final String ID_TOKEN = jwt(json("alg", "RS256"), json("sub", "uuid-dana"));

    /** What a fake endpoint received, and what it answers. */
    static final class Endpoint {
        Map<String, String> form;
        String authorization;
        final AtomicInteger calls = new AtomicInteger();
        Function<Map<String, String>, Reply> reply;
    }

    record Reply(int status, String body) {
        static Reply ok(JsonObject body) {
            return new Reply(200, body.toString());
        }
    }

    HttpServer server;
    Endpoint idp = new Endpoint();
    Endpoint as = new Endpoint();
    String base;

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/idp/token", x -> handle(x, idp));
        server.createContext("/as/token", x -> handle(x, as));
        server.start();
        base = "http://127.0.0.1:" + server.getAddress().getPort();
        idp.reply = form -> Reply.ok(idJagResponse(idJag(AUDIENCE, null)));
        as.reply = form -> Reply.ok(accessTokenResponse("atl-at.abc", 3600, "read:jira-work"));
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    IdJagExchange exchange(String idpScopes, String asScopes, boolean basic) {
        return new IdJagExchange(new IdJagExchange.Settings(
                base + "/idp/token", new IdJagExchange.Client("wso2-mcp-gateway", "is-secret", basic),
                AUDIENCE, idpScopes,
                base + "/as/token", new IdJagExchange.Client("wso2-mcp-gateway", "as-secret", basic),
                asScopes, Duration.ofSeconds(5), false));
    }

    IdJagExchange exchange() {
        return exchange("", "", false);
    }

    // --- the happy path ------------------------------------------------------------------------

    @Test
    void anIdTokenBecomesAnUpstreamAccessToken() throws Exception {
        IdJagExchange.AccessToken token = exchange().exchange(ID_TOKEN);

        assertEquals("atl-at.abc", token.value());
        assertEquals("Bearer", token.tokenType());
        assertEquals(3600, token.expiresIn());
        assertEquals(1, idp.calls.get());
        assertEquals(1, as.calls.get());
    }

    @Test
    void step1IsAnIdJagTokenExchangeAuthenticatedAsTheGateway() throws Exception {
        exchange().exchange(ID_TOKEN);

        assertEquals(IdJagExchange.GRANT_TOKEN_EXCHANGE, idp.form.get("grant_type"));
        assertEquals(ID_TOKEN, idp.form.get("subject_token"));
        assertEquals(IdJagExchange.TOKEN_TYPE_ID_TOKEN, idp.form.get("subject_token_type"));
        assertEquals(IdJagExchange.TOKEN_TYPE_ID_JAG, idp.form.get("requested_token_type"));
        assertEquals(AUDIENCE, idp.form.get("audience"));
        assertEquals("wso2-mcp-gateway", idp.form.get("client_id"));
        assertEquals("is-secret", idp.form.get("client_secret"));
        assertFalse(idp.form.containsKey("scope"));
    }

    @Test
    void step2IsAJwtBearerGrantCarryingTheIdJag() throws Exception {
        exchange().exchange(ID_TOKEN);

        assertEquals(IdJagExchange.GRANT_JWT_BEARER, as.form.get("grant_type"));
        assertEquals(idJag(AUDIENCE, null), as.form.get("assertion"));
        assertEquals("as-secret", as.form.get("client_secret"));
    }

    @Test
    void clientSecretBasicPutsCredentialsInTheHeaderNotTheForm() throws Exception {
        exchange("", "", true).exchange(ID_TOKEN);

        String expected = "Basic " + Base64.getEncoder()
                .encodeToString("wso2-mcp-gateway:is-secret".getBytes(StandardCharsets.UTF_8));
        assertEquals(expected, idp.authorization);
        assertFalse(idp.form.containsKey("client_secret"));
    }

    @Test
    void scopesAreSentWhenConfigured() throws Exception {
        idp.reply = form -> Reply.ok(idJagResponse(idJag(AUDIENCE, "read:jira-work read:me")));
        exchange("read:jira-work read:me", "read:jira-work", false).exchange(ID_TOKEN);

        assertEquals("read:jira-work read:me", idp.form.get("scope"));
        assertEquals("read:jira-work", as.form.get("scope"));
    }

    @Test
    void aRefreshTokenInTheUpstreamResponseIsIgnored() throws Exception {
        as.reply = form -> {
            JsonObject body = accessTokenResponse("atl-at.abc", 3600, null);
            body.addProperty("refresh_token", "atl-rt.should-not-exist");
            return Reply.ok(body);
        };
        assertEquals("atl-at.abc", exchange().exchange(ID_TOKEN).value());
    }

    @Test
    void secretsNeverAppearInToString() {
        IdJagExchange.Client client = new IdJagExchange.Client("id", "top-secret", false);
        assertFalse(client.toString().contains("top-secret"));
        IdJagExchange.AccessToken token = new IdJagExchange.AccessToken("atl-at.value", "Bearer", 1, "s");
        assertFalse(token.toString().contains("atl-at.value"));
    }

    // --- step 1: what the gateway refuses to pass on -------------------------------------------

    @Test
    void wrongIssuedTokenTypeStopsAtStep1() {
        idp.reply = form -> {
            JsonObject body = idJagResponse(idJag(AUDIENCE, null));
            body.addProperty("issued_token_type", "urn:ietf:params:oauth:token-type:access_token");
            return Reply.ok(body);
        };
        ExchangeException e = assertThrows(ExchangeException.class, () -> exchange().exchange(ID_TOKEN));
        assertStep1Config(e, "issued_token_type");
    }

    @Test
    void missingIssuedTokenTypeIsTolerated() throws Exception {
        idp.reply = form -> {
            JsonObject body = idJagResponse(idJag(AUDIENCE, null));
            body.remove("issued_token_type");
            return Reply.ok(body);
        };
        assertEquals("atl-at.abc", exchange().exchange(ID_TOKEN).value());
    }

    @Test
    void anIdJagNotTypedAsOneStopsAtStep1() {
        idp.reply = form -> Reply.ok(idJagResponse(jwt(json("typ", "JWT"), idJagClaims(AUDIENCE, null))));
        assertStep1Config(assertThrows(ExchangeException.class, () -> exchange().exchange(ID_TOKEN)), "typ");
    }

    @Test
    void anIdJagForAnotherAudienceStopsAtStep1() {
        idp.reply = form -> Reply.ok(idJagResponse(idJag("https://auth.example.org", null)));
        assertStep1Config(assertThrows(ExchangeException.class, () -> exchange().exchange(ID_TOKEN)),
                "does not match the configured audience");
    }

    @Test
    void anIdJagWithSeveralAudiencesStopsAtStep1() {
        JsonObject claims = idJagClaims(AUDIENCE, null);
        com.google.gson.JsonArray auds = new com.google.gson.JsonArray();
        auds.add(AUDIENCE);
        auds.add("https://auth.example.org");
        claims.add("aud", auds);
        idp.reply = form -> Reply.ok(idJagResponse(jwt(json("typ", IdJagExchange.ID_JAG_TYP), claims)));
        assertStep1Config(assertThrows(ExchangeException.class, () -> exchange().exchange(ID_TOKEN)),
                "exactly one aud");
    }

    @Test
    void anExpiredIdJagStopsAtStep1() {
        JsonObject claims = idJagClaims(AUDIENCE, null);
        claims.addProperty("exp", System.currentTimeMillis() / 1000 - 10);
        idp.reply = form -> Reply.ok(idJagResponse(jwt(json("typ", IdJagExchange.ID_JAG_TYP), claims)));
        assertStep1Config(assertThrows(ExchangeException.class, () -> exchange().exchange(ID_TOKEN)), "expired");
    }

    @Test
    void scopesBeyondTheIdJagAreRefusedBeforeStep2() {
        idp.reply = form -> Reply.ok(idJagResponse(idJag(AUDIENCE, "read:jira-work")));
        ExchangeException e = assertThrows(ExchangeException.class,
                () -> exchange("", "write:jira-work", false).exchange(ID_TOKEN));
        assertEquals(2, e.step());
        assertTrue(e.getMessage().contains("write:jira-work"));
        assertEquals(0, as.calls.get(), "the authorization server must not be called");
    }

    // --- error mapping: 401 means "sign in again", 502 means "not your fault" ------------------

    @Test
    void theIdpRejectingTheIdTokenAsksTheUserToSignInAgain() {
        idp.reply = form -> new Reply(400, oauthError("invalid_grant", "Signature validation failed").toString());
        ExchangeException e = assertThrows(ExchangeException.class, () -> exchange().exchange(ID_TOKEN));
        assertEquals(1, e.step());
        assertEquals("invalid_grant", e.oauthError());
        assertTrue(e.reauthenticate());
        assertEquals(401, e.httpStatus());
        assertEquals(0, as.calls.get());
    }

    @Test
    void anExpiredIdTokenAsksForSignInWithoutCallingTheIdp() {
        JsonObject claims = json("sub", "uuid-dana");
        claims.addProperty("exp", System.currentTimeMillis() / 1000 - 1);
        ExchangeException e = assertThrows(ExchangeException.class,
                () -> exchange().exchange(jwt(json("alg", "RS256"), claims)));
        assertEquals(1, e.step());
        assertEquals(401, e.httpStatus());
        assertEquals(0, idp.calls.get(), "the IdP must not be called");
    }

    @Test
    void aMalformedIdTokenAsksForSignInWithoutCallingTheIdp() {
        assertEquals(401, assertThrows(ExchangeException.class,
                () -> exchange().exchange("not.a-jwt")).httpStatus());
        assertEquals(0, idp.calls.get());
    }

    @Test
    void anIdpConfigurationErrorIsABadGateway() {
        idp.reply = form -> new Reply(401, oauthError("invalid_client", "Client authentication failed").toString());
        ExchangeException e = assertThrows(ExchangeException.class, () -> exchange().exchange(ID_TOKEN));
        assertFalse(e.reauthenticate());
        assertEquals(502, e.httpStatus());
    }

    @Test
    void anyStep2RejectionIsABadGatewayEvenInvalidGrant() {
        as.reply = form -> new Reply(400, oauthError("invalid_grant", "The ID-JAG has already been used").toString());
        ExchangeException e = assertThrows(ExchangeException.class, () -> exchange().exchange(ID_TOKEN));
        assertEquals(2, e.step());
        assertEquals("invalid_grant", e.oauthError());
        assertEquals(502, e.httpStatus());
    }

    @Test
    void anUnreachableIdpIsABadGateway() {
        server.stop(0);
        ExchangeException e = assertThrows(ExchangeException.class, () -> exchange().exchange(ID_TOKEN));
        assertEquals(1, e.step());
        assertNull(e.oauthError());
        assertEquals(502, e.httpStatus());
    }

    @Test
    void aNonJsonAnswerIsABadGateway() {
        as.reply = form -> new Reply(200, "<html>proxy error</html>");
        assertEquals(502, assertThrows(ExchangeException.class, () -> exchange().exchange(ID_TOKEN)).httpStatus());
    }

    @Test
    void requiredSettingsAreCheckedUpFront() {
        assertThrows(IllegalArgumentException.class, () -> new IdJagExchange(new IdJagExchange.Settings(
                base + "/idp/token", new IdJagExchange.Client("c", "s", false), "",
                "", base + "/as/token", new IdJagExchange.Client("c", "s", false), "",
                Duration.ofSeconds(1), false)));
    }

    // --- fakes and helpers ---------------------------------------------------------------------

    private static void assertStep1Config(ExchangeException e, String fragment) {
        assertEquals(1, e.step());
        assertFalse(e.reauthenticate());
        assertEquals(502, e.httpStatus());
        assertTrue(e.getMessage().contains(fragment), e.getMessage());
    }

    private static void handle(HttpExchange x, Endpoint endpoint) throws IOException {
        endpoint.calls.incrementAndGet();
        endpoint.authorization = x.getRequestHeaders().getFirst("Authorization");
        endpoint.form = parseForm(new String(x.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
        Reply reply = endpoint.reply.apply(endpoint.form);
        byte[] bytes = reply.body().getBytes(StandardCharsets.UTF_8);
        x.getResponseHeaders().add("Content-Type", "application/json");
        x.sendResponseHeaders(reply.status(), bytes.length);
        try (OutputStream out = x.getResponseBody()) {
            out.write(bytes);
        }
    }

    private static Map<String, String> parseForm(String body) {
        Map<String, String> form = new HashMap<>();
        for (String pair : body.split("&")) {
            String[] kv = pair.split("=", 2);
            form.put(URLDecoder.decode(kv[0], StandardCharsets.UTF_8),
                    kv.length > 1 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "");
        }
        return form;
    }

    static JsonObject idJagClaims(String aud, String scope) {
        long now = System.currentTimeMillis() / 1000;
        JsonObject claims = new JsonObject();
        claims.addProperty("iss", "https://localhost:9444/oauth2/token");
        claims.addProperty("sub", "dana@example.com");
        claims.addProperty("aud", aud);
        claims.addProperty("client_id", "wso2-mcp-gateway");
        claims.addProperty("iat", now);
        claims.addProperty("exp", now + 300);
        claims.addProperty("jti", "jti-1");
        if (scope != null) {
            claims.addProperty("scope", scope);
        }
        return claims;
    }

    static String idJag(String aud, String scope) {
        return jwt(json("typ", IdJagExchange.ID_JAG_TYP), idJagClaims(aud, scope));
    }

    static JsonObject idJagResponse(String idJag) {
        JsonObject body = new JsonObject();
        body.addProperty("access_token", idJag);
        body.addProperty("issued_token_type", IdJagExchange.TOKEN_TYPE_ID_JAG);
        body.addProperty("token_type", "N_A");
        body.addProperty("expires_in", 300);
        return body;
    }

    static JsonObject accessTokenResponse(String token, int expiresIn, String scope) {
        JsonObject body = new JsonObject();
        body.addProperty("access_token", token);
        body.addProperty("token_type", "Bearer");
        body.addProperty("expires_in", expiresIn);
        if (scope != null) {
            body.addProperty("scope", scope);
        }
        return body;
    }

    static JsonObject oauthError(String error, String description) {
        JsonObject body = new JsonObject();
        body.addProperty("error", error);
        body.addProperty("error_description", description);
        return body;
    }

    static JsonObject json(String key, String value) {
        JsonObject o = new JsonObject();
        o.addProperty(key, value);
        return o;
    }

    /** An unsigned-looking JWT: the gateway never verifies signatures, the authorization server does. */
    static String jwt(JsonObject header, JsonObject claims) {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        return b64.encodeToString(header.toString().getBytes(StandardCharsets.UTF_8)) + "."
                + b64.encodeToString(claims.toString().getBytes(StandardCharsets.UTF_8)) + ".c2ln";
    }

    @Test
    void validateIdJagReturnsTheScopesItCarries() throws Exception {
        assertEquals(List.of("read:jira-work", "read:me"),
                IdJagExchange.validateIdJag(idJag(AUDIENCE, "read:jira-work read:me"), AUDIENCE));
        assertEquals(List.of(), IdJagExchange.validateIdJag(idJag(AUDIENCE, null), AUDIENCE));
    }
}
