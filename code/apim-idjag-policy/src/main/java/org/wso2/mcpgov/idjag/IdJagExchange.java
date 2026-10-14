package org.wso2.mcpgov.idjag;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Turns a user's ID token into an access token for the upstream MCP server, in two calls.
 *
 * <pre>
 *   step 1  RFC 8693 token exchange at the IdP (WSO2 IS):  ID token in, ID-JAG out
 *   step 2  RFC 7523 jwt-bearer grant at the resource's authorization server (Atlassian):
 *           ID-JAG in, access token out
 * </pre>
 *
 * <p>A Java port of the ID token path of
 * <a href="https://github.com/DinikaSen/id-jag-token-exchange-policy">id-jag-token-exchange-policy</a>
 * (commit 5dd5513), which is written in Go for the WSO2 API Platform gateway. The refresh token
 * path, the token cache, single-flight and retries are not ported.
 *
 * <p>No Synapse types here, so this class is tested on its own. {@link IdJagTokenMediator} adapts
 * it to the APIM gateway. Token values are never logged.
 */
public final class IdJagExchange {

    private static final Log log = LogFactory.getLog(IdJagExchange.class);

    public static final String GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    public static final String GRANT_JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    public static final String TOKEN_TYPE_ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token";
    public static final String TOKEN_TYPE_ID_JAG = "urn:ietf:params:oauth:token-type:id-jag";
    public static final String ID_JAG_TYP = "oauth-id-jag+jwt";

    /** A confidential client: the gateway's registration at one authorization server. */
    public record Client(String id, String secret, boolean basicAuth) {
        @Override
        public String toString() {
            return "Client[id=" + id + "]"; // never the secret
        }
    }

    /** Everything the exchange needs. Scopes may be empty. */
    public record Settings(String idpTokenEndpoint, Client idpClient, String audience, String idpScopes,
                           String resourceAsTokenEndpoint, Client resourceAsClient, String resourceAsScopes,
                           Duration timeout, boolean tlsInsecureSkipVerify) {
    }

    /** The upstream access token step 2 returned. */
    public record AccessToken(String value, String tokenType, long expiresIn, String scope) {
        @Override
        public String toString() {
            return "AccessToken[type=" + tokenType + ", expiresIn=" + expiresIn + ", scope=" + scope + "]";
        }
    }

    private final Settings settings;
    private final HttpClient http;

    public IdJagExchange(Settings settings) {
        require(settings.idpTokenEndpoint(), "idpTokenEndpoint");
        require(settings.audience(), "audience");
        require(settings.resourceAsTokenEndpoint(), "resourceAsTokenEndpoint");
        require(settings.idpClient() == null ? null : settings.idpClient().id(), "idpClientId");
        require(settings.resourceAsClient() == null ? null : settings.resourceAsClient().id(), "resourceAsClientId");
        this.settings = settings;
        this.http = buildClient(settings);
    }

    /** Steps 1 and 2. Throws with the step that failed and the HTTP status the caller should get. */
    public AccessToken exchange(String idToken) throws ExchangeException {
        requireUnexpired(idToken);
        IdJag idJag = requestIdJag(idToken);
        return redeem(idJag);
    }

    /**
     * An expired ID token is the everyday reason step 1 fails, and only signing in again fixes
     * it. WSO2 IS reports it as {@code invalid_request} (RFC 8693 section 2.2.2 uses that code for
     * any unacceptable subject token), which cannot be told apart from a gateway
     * misconfiguration, so it is caught here, before calling the IdP, and answered with a 401.
     */
    static void requireUnexpired(String idToken) throws ExchangeException {
        JsonObject claims;
        try {
            claims = jwtPart(idToken, 1);
        } catch (ExchangeException e) {
            throw new ExchangeException(1, null, "the ID token is not a JWT", true);
        }
        JsonElement exp = claims.get("exp");
        if (exp != null && exp.isJsonPrimitive() && exp.getAsJsonPrimitive().isNumber()
                && exp.getAsLong() <= System.currentTimeMillis() / 1000) {
            throw new ExchangeException(1, null, "the ID token has expired", true);
        }
    }

    // --- step 1 --------------------------------------------------------------------------------

    record IdJag(String jwt, List<String> scopes) {
    }

    IdJag requestIdJag(String idToken) throws ExchangeException {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", GRANT_TOKEN_EXCHANGE);
        form.put("subject_token", idToken);
        form.put("subject_token_type", TOKEN_TYPE_ID_TOKEN);
        form.put("requested_token_type", TOKEN_TYPE_ID_JAG);
        form.put("audience", settings.audience());
        if (!blank(settings.idpScopes())) {
            form.put("scope", settings.idpScopes());
        }
        JsonObject body = post(1, settings.idpTokenEndpoint(), settings.idpClient(), form);

        String issuedType = string(body, "issued_token_type");
        if (issuedType == null) {
            log.warn("ID-JAG response omits issued_token_type, which the profile requires");
        } else if (!TOKEN_TYPE_ID_JAG.equals(issuedType)) {
            throw new ExchangeException(1, null,
                    "IdP returned issued_token_type " + issuedType + ", expected " + TOKEN_TYPE_ID_JAG, false);
        }
        String jwt = string(body, "access_token");
        if (jwt == null) {
            throw new ExchangeException(1, null, "IdP response has no access_token (the ID-JAG)", false);
        }
        List<String> scopes = validateIdJag(jwt, settings.audience());
        if (scopes.isEmpty() && string(body, "scope") != null) {
            scopes = List.of(string(body, "scope").trim().split("\\s+"));
        }
        return new IdJag(jwt, scopes);
    }

    /**
     * Checks what the resource's authorization server will check, so a misconfiguration fails
     * here with a precise message instead of an opaque rejection in step 2: typ, a single aud
     * equal to the configured audience, and an unexpired exp. The signature is not checked here;
     * that is the authorization server's job, against the IdP's published keys.
     *
     * @return the scopes the ID-JAG carries, possibly none.
     */
    static List<String> validateIdJag(String jwt, String audience) throws ExchangeException {
        JsonObject header = jwtPart(jwt, 0);
        JsonObject claims = jwtPart(jwt, 1);

        String typ = string(header, "typ");
        if (!ID_JAG_TYP.equalsIgnoreCase(typ)) {
            throw new ExchangeException(1, null, "ID-JAG typ is " + typ + ", expected " + ID_JAG_TYP, false);
        }
        List<String> auds = strings(claims.get("aud"));
        if (auds.size() != 1) {
            throw new ExchangeException(1, null, "ID-JAG must have exactly one aud, has " + auds.size(), false);
        }
        if (!auds.get(0).equals(audience)) {
            throw new ExchangeException(1, null,
                    "ID-JAG aud " + auds.get(0) + " does not match the configured audience " + audience, false);
        }
        JsonElement exp = claims.get("exp");
        if (exp == null || !exp.isJsonPrimitive() || !exp.getAsJsonPrimitive().isNumber()) {
            throw new ExchangeException(1, null, "ID-JAG has no exp", false);
        }
        if (exp.getAsLong() <= System.currentTimeMillis() / 1000) {
            throw new ExchangeException(1, null, "ID-JAG is already expired", false);
        }
        String scope = string(claims, "scope");
        return blank(scope) ? List.of() : List.of(scope.trim().split("\\s+"));
    }

    // --- step 2 --------------------------------------------------------------------------------

    AccessToken redeem(IdJag idJag) throws ExchangeException {
        String asked = settings.resourceAsScopes();
        if (!blank(asked) && !idJag.scopes().isEmpty()) {
            List<String> outside = new ArrayList<>();
            for (String s : asked.trim().split("\\s+")) {
                if (!idJag.scopes().contains(s)) {
                    outside.add(s);
                }
            }
            if (!outside.isEmpty()) {
                throw new ExchangeException(2, null, "resourceAsScopes " + outside
                        + " are not within the ID-JAG's scope " + idJag.scopes(), false);
            }
        }
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", GRANT_JWT_BEARER);
        form.put("assertion", idJag.jwt());
        if (!blank(asked)) {
            form.put("scope", asked);
        }
        JsonObject body = post(2, settings.resourceAsTokenEndpoint(), settings.resourceAsClient(), form);

        String value = string(body, "access_token");
        if (value == null) {
            throw new ExchangeException(2, null, "authorization server response has no access_token", false);
        }
        JsonElement expiresIn = body.get("expires_in");
        long seconds = expiresIn != null && expiresIn.isJsonPrimitive() ? expiresIn.getAsLong() : 0;
        if (string(body, "refresh_token") != null) {
            log.warn("authorization server returned a refresh_token for an ID-JAG; discarded");
        }
        return new AccessToken(value, string(body, "token_type"), seconds, string(body, "scope"));
    }

    // --- HTTP ----------------------------------------------------------------------------------

    private JsonObject post(int step, String endpoint, Client client, Map<String, String> form)
            throws ExchangeException {
        Map<String, String> fields = new LinkedHashMap<>(form);
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(endpoint))
                .timeout(settings.timeout())
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json");
        if (client.basicAuth()) {
            String pair = encode(client.id()) + ":" + encode(client.secret());
            request.header("Authorization",
                    "Basic " + Base64.getEncoder().encodeToString(pair.getBytes(StandardCharsets.UTF_8)));
        } else {
            fields.put("client_id", client.id());
            fields.put("client_secret", client.secret());
        }
        String encoded = fields.entrySet().stream()
                .map(e -> encode(e.getKey()) + "=" + encode(e.getValue()))
                .collect(Collectors.joining("&"));

        HttpResponse<String> response;
        try {
            response = http.send(request.POST(HttpRequest.BodyPublishers.ofString(encoded)).build(),
                    HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new ExchangeException(step, null, "could not reach " + endpoint + ": " + e.getMessage(), false);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ExchangeException(step, null, "interrupted calling " + endpoint, false);
        }

        JsonObject body = parseObject(response.body());
        if (response.statusCode() / 100 != 2) {
            String error = body == null ? null : string(body, "error");
            String description = body == null ? null : string(body, "error_description");
            // Only the IdP rejecting the user's assertion can be fixed by the user signing in
            // again. Everything else, including any step 2 rejection, is trust or configuration.
            boolean reauth = step == 1 && ("invalid_grant".equals(error) || "interaction_required".equals(error));
            throw new ExchangeException(step, error, "HTTP " + response.statusCode()
                    + (error == null ? "" : " " + error) + (description == null ? "" : ": " + description), reauth);
        }
        if (body == null) {
            throw new ExchangeException(step, null, endpoint + " did not return a JSON object", false);
        }
        return body;
    }

    private static HttpClient buildClient(Settings settings) {
        HttpClient.Builder builder = HttpClient.newBuilder()
                // HTTP/1.1 always. The JDK client's default tries an h2c upgrade on plain http://,
                // which servers that do not support it (uvicorn, for one) answer by dropping the
                // request body, so the token endpoint sees no credentials.
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(settings.timeout())
                .followRedirects(HttpClient.Redirect.NEVER);
        if (settings.tlsInsecureSkipVerify()) {
            // Local development only: the local IS uses a self-signed certificate. In APIM, import
            // the IdP's certificate into the gateway's trust store instead.
            builder.sslContext(trustAll());
        }
        return builder.build();
    }

    private static SSLContext trustAll() {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[]{new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) {
                }

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            }}, null);
            return context;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    // --- small helpers -------------------------------------------------------------------------

    static JsonObject jwtPart(String jwt, int index) throws ExchangeException {
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            throw new ExchangeException(1, null, "ID-JAG is not a JWT", false);
        }
        try {
            String json = new String(Base64.getUrlDecoder().decode(parts[index]), StandardCharsets.UTF_8);
            return JsonParser.parseString(json).getAsJsonObject();
        } catch (RuntimeException e) {
            throw new ExchangeException(1, null, "ID-JAG part " + index + " is not decodable JSON", false);
        }
    }

    private static JsonObject parseObject(String text) {
        try {
            JsonElement parsed = JsonParser.parseString(text);
            return parsed.isJsonObject() ? parsed.getAsJsonObject() : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static String string(JsonObject object, String name) {
        JsonElement value = object.get(name);
        return value != null && value.isJsonPrimitive() ? value.getAsString() : null;
    }

    private static List<String> strings(JsonElement value) {
        List<String> out = new ArrayList<>();
        if (value == null || value.isJsonNull()) {
            return out;
        }
        if (value.isJsonArray()) {
            JsonArray array = value.getAsJsonArray();
            array.forEach(e -> out.add(e.getAsString()));
        } else {
            out.add(value.getAsString());
        }
        return out;
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }

    private static void require(String value, String name) {
        if (blank(value)) {
            throw new IllegalArgumentException(name + " is required");
        }
    }
}
