package org.wso2.mcpgov.idjag;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.wso2.mcpgov.idjag.IdJagExchangeTest.json;
import static org.wso2.mcpgov.idjag.IdJagExchangeTest.jwt;

/**
 * Keeping each user's ID token at sign-in, and the metadata that makes the client sign in through
 * the gateway: {@link IdTokenStore}, {@link IdpProxyMediator}, and the resource metadata of
 * {@link IdJagTokenMediator}.
 */
class IdTokenCaptureTest {

    private static final long NOW = 1_800_000_000L;
    private static final String DANA = "076b092e-7d0d-4ec6-8f1a-8b651092b70b";

    private final IdTokenStore store =
            new IdTokenStore(Clock.fixed(Instant.ofEpochSecond(NOW), ZoneOffset.UTC));

    private static String idToken(String sub, long exp) {
        JsonObject claims = new JsonObject();
        if (sub != null) {
            claims.addProperty("sub", sub);
        }
        claims.addProperty("aud", "wso2-mcp-gateway");
        claims.addProperty("exp", exp);
        return jwt(json("alg", "RS256"), claims);
    }

    // --- IdTokenStore ----------------------------------------------------------------------------

    @Test
    void keepsTheIdTokenUnderItsSubject() {
        String token = idToken(DANA, NOW + 3600);
        assertEquals(DANA, store.put(token));
        assertEquals(token, store.get(DANA));
        assertNull(store.get("someone-else"));
    }

    @Test
    void aRefreshReplacesTheOlderIdToken() {
        String first = idToken(DANA, NOW + 600);
        String refreshed = idToken(DANA, NOW + 3600);
        store.put(first);
        store.put(refreshed);
        assertEquals(refreshed, store.get(DANA));
        store.put(first); // an older response arriving late does not win
        assertEquals(refreshed, store.get(DANA));
    }

    @Test
    void expiredOrUnusableIdTokensAreNotKept() {
        assertNull(store.put(idToken(DANA, NOW)));
        assertNull(store.put(idToken(null, NOW + 3600)));
        assertNull(store.put("not-a-jwt"));
        assertEquals(0, store.size());
    }

    @Test
    void anIdTokenThatExpiresWhileStoredIsNotHandedOut() {
        long[] now = {NOW};
        IdTokenStore ticking = new IdTokenStore(new Clock() {
            @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
            @Override public Clock withZone(java.time.ZoneId zone) { return this; }
            @Override public Instant instant() { return Instant.ofEpochSecond(now[0]); }
        });
        String token = idToken(DANA, NOW + 3600);
        ticking.put(token);
        now[0] = NOW + 3599;
        assertEquals(token, ticking.get(DANA));
        now[0] = NOW + 3600;
        assertNull(ticking.get(DANA));
        assertEquals(0, ticking.size());
    }

    @Test
    void apimUsernamesMapBackToTheIsSubject() {
        assertEquals(DANA, IdTokenStore.subjectOf(DANA + "@carbon.super", "carbon.super"));
        assertEquals("dana@example.com", IdTokenStore.subjectOf("dana@example.com@carbon.super", "carbon.super"));
        assertEquals(DANA, IdTokenStore.subjectOf(DANA, "carbon.super"));
        assertEquals(DANA, IdTokenStore.subjectOfJwt(idToken(DANA, NOW + 60)));
        assertNull(IdTokenStore.subjectOfJwt("opaque"));
    }

    // --- IdpProxyMediator ------------------------------------------------------------------------

    @Test
    void aTokenResponseLeavesItsIdTokenInTheStore() {
        JsonObject response = new JsonObject();
        response.addProperty("access_token", "at");
        response.addProperty("id_token", idToken(DANA, NOW + 3600));
        assertEquals(DANA, IdpProxyMediator.keepIdToken(response, store));
        assertTrue(store.get(DANA) != null);
    }

    @Test
    void metadataSendsTokenCallsThroughTheGatewayAndDropsRegistration() {
        JsonObject is = JsonParser.parseString("""
                {"issuer":"https://localhost:9444/oauth2/token",
                 "authorization_endpoint":"https://localhost:9444/oauth2/authorize",
                 "token_endpoint":"https://localhost:9444/oauth2/token",
                 "registration_endpoint":"https://localhost:9444/api/identity/oauth2/dcr/v1.1/register"}
                """).getAsJsonObject();

        JsonObject seen = IdpProxyMediator.rewriteMetadata(is, "https://localhost:8243/idp/");

        assertEquals("https://localhost:8243/idp/oauth2/token", seen.get("token_endpoint").getAsString());
        assertEquals("https://localhost:9444/oauth2/authorize", seen.get("authorization_endpoint").getAsString(),
                "sign-in stays at IS");
        assertEquals("https://localhost:9444/oauth2/token", seen.get("issuer").getAsString());
        assertFalse(seen.has("registration_endpoint"));
        assertTrue(is.has("registration_endpoint"), "the input is not modified");
    }

    // --- resource metadata -------------------------------------------------------------------------

    @Test
    void resourceMetadataPointsAtTheGatewayAndAsksForOpenid() {
        JsonObject metadata = IdJagTokenMediator.resourceMetadata("https://localhost:8243/atlassian-rovo/v1/mcp",
                "https://localhost:8243/idp/oauth2/token", " openid  jira:read openid default ");

        assertEquals("https://localhost:8243/atlassian-rovo/v1/mcp", metadata.get("resource").getAsString());
        assertEquals("[\"https://localhost:8243/idp/oauth2/token\"]", metadata.get("authorization_servers").toString());
        assertEquals("[\"openid\",\"jira:read\",\"default\"]", metadata.get("scopes_supported").toString());
    }
}
