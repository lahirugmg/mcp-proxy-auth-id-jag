package org.wso2.mcpgov.idjag;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.time.Clock;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Each user's latest ID token, kept by the gateway as IS's token responses pass through it
 * ({@link IdpProxyMediator}) and read on {@code tools/call} ({@link IdJagTokenMediator}).
 *
 * <p>Keyed by the ID token's {@code sub}, which is the subject of the user's IS access token too:
 * APIM authenticates that access token and names the user {@code <sub>@<tenant domain>}.
 *
 * <p>In memory: per gateway node, and empty after a restart. A user with no stored ID token gets
 * a 401 and signs in again. Several gateway nodes would need a shared store instead.
 */
final class IdTokenStore {

    /** One store per gateway: both mediators are loaded from the same jar in components/lib. */
    private static final IdTokenStore SHARED = new IdTokenStore(Clock.systemUTC());

    private record Entry(String idToken, long exp) {
    }

    private final Map<String, Entry> bySubject = new ConcurrentHashMap<>();
    private final Clock clock;

    IdTokenStore(Clock clock) {
        this.clock = clock;
    }

    static IdTokenStore shared() {
        return SHARED;
    }

    /**
     * Keep an ID token under its {@code sub}, replacing an older one. Returns that {@code sub},
     * or null when the value is not an unexpired JWT with {@code sub} and {@code exp}.
     */
    String put(String idToken) {
        JsonObject claims;
        try {
            claims = IdJagExchange.jwtPart(idToken, 1);
        } catch (ExchangeException | RuntimeException e) {
            return null;
        }
        String sub = string(claims, "sub");
        long exp = number(claims, "exp");
        if (sub == null || exp <= now()) {
            return null;
        }
        bySubject.entrySet().removeIf(e -> e.getValue().exp() <= now()); // keeps the map small
        bySubject.merge(sub, new Entry(idToken, exp), (old, fresh) -> fresh.exp() >= old.exp() ? fresh : old);
        return sub;
    }

    /** The user's unexpired ID token, or null. */
    String get(String sub) {
        if (sub == null) {
            return null;
        }
        Entry entry = bySubject.get(sub);
        if (entry == null) {
            return null;
        }
        if (entry.exp() <= now()) {
            bySubject.remove(sub, entry);
            return null;
        }
        return entry.idToken();
    }

    /**
     * The IS subject of an APIM username: APIM appends the tenant domain to the token's
     * {@code sub}, so {@code 076b…@carbon.super} becomes {@code 076b…}.
     */
    static String subjectOf(String apimUsername, String tenantDomain) {
        if (apimUsername == null) {
            return null;
        }
        String suffix = "@" + tenantDomain;
        return apimUsername.endsWith(suffix)
                ? apimUsername.substring(0, apimUsername.length() - suffix.length()) : apimUsername;
    }

    /** The {@code sub} of a JWT, or null. */
    static String subjectOfJwt(String jwt) {
        try {
            return string(IdJagExchange.jwtPart(jwt, 1), "sub");
        } catch (ExchangeException | RuntimeException e) {
            return null;
        }
    }

    int size() {
        return bySubject.size();
    }

    private long now() {
        return clock.millis() / 1000;
    }

    private static String string(JsonObject object, String name) {
        JsonElement value = object.get(name);
        return value != null && value.isJsonPrimitive() ? value.getAsString() : null;
    }

    private static long number(JsonObject object, String name) {
        JsonElement value = object.get(name);
        return value != null && value.isJsonPrimitive() && value.getAsJsonPrimitive().isNumber()
                ? value.getAsLong() : 0;
    }
}
