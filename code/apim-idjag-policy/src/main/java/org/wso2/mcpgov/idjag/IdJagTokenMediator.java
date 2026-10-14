package org.wso2.mcpgov.idjag;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.core.axis2.Axis2Sender;
import org.apache.synapse.mediators.AbstractMediator;
import org.wso2.carbon.apimgt.gateway.APIMgtGatewayConstants;
import org.wso2.carbon.apimgt.gateway.handlers.security.APISecurityUtils;
import org.wso2.carbon.apimgt.gateway.handlers.security.AuthenticationContext;

import java.time.Duration;
import java.util.Map;
import java.util.TreeMap;

/**
 * The APIM 4.6.0 gateway side of the ID-JAG flow: on every MCP {@code tools/call}, swap the
 * client's gateway token for the user's own upstream (Atlassian) token.
 *
 * <p>Runs after APIM has authenticated the gateway token. A custom gateway policy renders it:
 *
 * <pre>
 *   &lt;class name="org.wso2.mcpgov.idjag.IdJagTokenMediator"&gt;
 *     &lt;property name="idpTokenEndpoint" value="https://localhost:9444/oauth2/token"/&gt;
 *     ...
 *   &lt;/class&gt;
 * </pre>
 *
 * <p>Where the user's ID token comes from: the {@link IdTokenStore}, filled by
 * {@link IdpProxyMediator} when the user signed in through the gateway's {@code /idp} API. An
 * {@code X-ID-Token} request header (the Go policy's ID token mode) is still accepted, for tests
 * and clients that hold the ID token themselves; either way it must name the authenticated user.
 *
 * <p>When {@code authorizationServer} is set, it also answers the MCP server's resource metadata
 * ({@code /.well-known/oauth-protected-resource}) itself, before APIM does: the client is sent to
 * sign in through the gateway's {@code /idp} API, and {@code openid} is among the scopes, so that
 * the sign-in returns an ID token. APIM's own answer names no sign-in server while the MCP server
 * accepts any key manager, and never asks for {@code openid}.
 *
 * <p>Discovery ({@code initialize}, {@code tools/list}, {@code ping}) passes through untouched.
 */
public class IdJagTokenMediator extends AbstractMediator {

    private static final Log log = LogFactory.getLog(IdJagTokenMediator.class);

    static final String TOOLS_CALL = "tools/call";
    static final String RESOURCE_METADATA_PATH = "/.well-known/oauth-protected-resource";

    // --- Synapse properties (set from the gateway policy) -------------------------------------
    private String idpTokenEndpoint;
    private String idpClientId;
    private String idpClientSecret;
    private String idpClientAuthMethod = "client_secret_post";
    private String audience;
    private String idpScopes = "";
    private String resourceAsTokenEndpoint;
    private String resourceAsClientId;
    private String resourceAsClientSecret;
    private String resourceAsClientAuthMethod = "client_secret_post";
    private String resourceAsScopes = "";
    private String idTokenHeader = "X-ID-Token";
    private String headerName = "Authorization";
    private String valuePrefix = "Bearer";
    private int timeoutMillis = 10000;
    private boolean tlsInsecureSkipVerify = false;
    private String authorizationServer = "";
    private String scopesSupported = "openid";

    private final IdTokenStore store;
    private volatile IdJagExchange exchange;

    public IdJagTokenMediator() {
        this(IdTokenStore.shared());
    }

    IdJagTokenMediator(IdTokenStore store) {
        this.store = store;
    }

    @Override
    public boolean mediate(MessageContext messageContext) {
        if (!authorizationServer.isEmpty()) {
            String resource = resourceFor(messageContext);
            if (resource != null) {
                return respond(messageContext, 200,
                        resourceMetadata(resource, authorizationServer, scopesSupported).toString(), false);
            }
        }
        if (!TOOLS_CALL.equals(messageContext.getProperty(APIMgtGatewayConstants.MCP_METHOD))) {
            return true;
        }

        String user = enterpriseUser(messageContext);
        if (user == null) {
            // A client_credentials token reached a tool call. An ID-JAG names a person; there
            // is no person here.
            return respond(messageContext, 403, jsonRpcError(messageContext, -32001,
                    "Atlassian tools need a person's sign-in; this token identifies an application"), false);
        }

        Map<String, Object> headers = transportHeaders(messageContext);
        String subject = IdTokenStore.subjectOf(user, tenantDomain(messageContext));
        String idToken = bearerFrom(header(headers, idTokenHeader));
        String source = idTokenHeader + " header";
        if (idToken != null) {
            // The ID-JAG is issued for the ID token's subject, so it must be the caller's own.
            if (!looksLikeJwt(idToken) || !subject.equals(IdTokenStore.subjectOfJwt(idToken))) {
                log.warn("ID-JAG: the ID token in " + idTokenHeader + " does not name " + user);
                return respond(messageContext, 403, jsonRpcError(messageContext, -32001,
                        "The ID token sent does not belong to the signed-in user"), false);
            }
        } else {
            idToken = store.get(subject);
            source = "kept at sign-in";
            if (idToken == null) {
                log.warn("ID-JAG: no stored ID token for " + user);
                return respond(messageContext, 401, jsonRpcError(messageContext, -32001,
                        "Sign in again: the gateway has no ID token for this session"), true);
            }
        }

        IdJagExchange.AccessToken token;
        try {
            token = exchange().exchange(idToken);
        } catch (ExchangeException e) {
            log.warn("ID-JAG: step " + e.step() + " failed for " + user + ": " + e.getMessage());
            String message = e.reauthenticate()
                    ? "Sign in again: the identity provider no longer accepts this session"
                    : "The upstream authorization could not be obtained; contact the administrator";
            return respond(messageContext, e.httpStatus(), jsonRpcError(messageContext, -32001, message),
                    e.reauthenticate());
        }

        // The upstream must see neither the gateway token nor the user's ID token.
        removeHeader(headers, idTokenHeader);
        removeHeader(headers, headerName);
        headers.put(headerName, valuePrefix.isEmpty() ? token.value() : valuePrefix + " " + token.value());
        // One line per exchange, never a token value: the gateway's own record of hops 1 and 2.
        log.info("ID-JAG: tools/call " + toolName(messageContext) + " for " + user + ": ID token ("
                + source + ") -> ID-JAG -> upstream token, scope \"" + token.scope() + "\", expires in "
                + token.expiresIn() + " s");
        return true;
    }

    // --- request inspection --------------------------------------------------------------------

    /**
     * The authenticated person, or null when the caller is an application: a
     * {@code client_credentials} token has the consumer key as its username.
     */
    private static String enterpriseUser(MessageContext messageContext) {
        Object raw = messageContext.getProperty(APISecurityUtils.API_AUTH_CONTEXT);
        if (raw instanceof AuthenticationContext context) {
            String username = context.getUsername();
            if (username == null || username.isEmpty()) {
                return null;
            }
            String consumerKey = context.getConsumerKey();
            return consumerKey != null && consumerKey.equals(username) ? null : username;
        }
        Object userId = messageContext.getProperty(APIMgtGatewayConstants.USER_ID);
        return userId == null || userId.toString().isEmpty() ? null : userId.toString();
    }

    private static String tenantDomain(MessageContext messageContext) {
        Object domain = messageContext.getProperty(APIMgtGatewayConstants.TENANT_DOMAIN);
        return domain == null || domain.toString().isEmpty() ? "carbon.super" : domain.toString();
    }

    /**
     * The MCP server URL whose resource metadata is being asked for, or null for any other
     * request: {@code /atlassian-rovo/v1/.well-known/oauth-protected-resource} is the metadata of
     * {@code https://<host>/atlassian-rovo/v1/mcp}, the URL APIM itself puts in it.
     */
    private static String resourceFor(MessageContext messageContext) {
        Object raw = messageContext.getProperty(org.apache.synapse.rest.RESTConstants.REST_FULL_REQUEST_PATH);
        if (raw == null) {
            return null;
        }
        String path = raw.toString();
        int query = path.indexOf('?');
        if (query >= 0) {
            path = path.substring(0, query);
        }
        if (!path.endsWith(RESOURCE_METADATA_PATH)) {
            return null;
        }
        String host = header(transportHeaders(messageContext), "Host");
        return host == null ? null
                : "https://" + host + path.substring(0, path.length() - RESOURCE_METADATA_PATH.length()) + "/mcp";
    }

    /** RFC 9728 resource metadata that sends the client to sign in through the gateway. */
    static JsonObject resourceMetadata(String resource, String authorizationServer, String scopesSupported) {
        JsonObject metadata = new JsonObject();
        metadata.addProperty("resource", resource);
        JsonArray servers = new JsonArray();
        servers.add(authorizationServer);
        metadata.add("authorization_servers", servers);
        JsonArray scopes = new JsonArray();
        for (String scope : scopesSupported.trim().split("\\s+")) {
            if (!scope.isEmpty() && !scopes.contains(new JsonPrimitive(scope))) {
                scopes.add(scope);
            }
        }
        metadata.add("scopes_supported", scopes);
        JsonArray methods = new JsonArray();
        methods.add("header");
        metadata.add("bearer_methods_supported", methods);
        return metadata;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> transportHeaders(MessageContext messageContext) {
        org.apache.axis2.context.MessageContext axis2 =
                ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        Object raw = axis2.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
        if (raw instanceof Map) {
            return (Map<String, Object>) raw;
        }
        Map<String, Object> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        axis2.setProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS, headers);
        return headers;
    }

    /** Case-insensitive lookup: transport header maps usually are, but not always. */
    static String header(Map<String, Object> headers, String name) {
        for (Map.Entry<String, Object> e : headers.entrySet()) {
            if (name.equalsIgnoreCase(e.getKey()) && e.getValue() != null) {
                return e.getValue().toString();
            }
        }
        return null;
    }

    static void removeHeader(Map<String, Object> headers, String name) {
        headers.entrySet().removeIf(e -> name.equalsIgnoreCase(e.getKey()));
    }

    /** The token in a header value, tolerating a {@code Bearer } prefix, or null. */
    static String bearerFrom(String value) {
        if (value == null) {
            return null;
        }
        String v = value.trim();
        if (v.equalsIgnoreCase("Bearer")) {
            return null; // "Bearer " with nothing after it, trimmed
        }
        if (v.regionMatches(true, 0, "Bearer ", 0, 7)) {
            v = v.substring(7).trim();
        }
        return v.isEmpty() ? null : v;
    }

    static boolean looksLikeJwt(String value) {
        return value.split("\\.", -1).length == 3;
    }

    // --- answering the MCP client directly -----------------------------------------------------

    /**
     * Answer the client and stop the sequence; returning false keeps Synapse from calling the
     * backend. Response headers start empty, so nothing from the request (the gateway token, the
     * ID token) is echoed back.
     */
    private static boolean respond(MessageContext messageContext, int status, String body,
                                   boolean askToSignIn) {
        org.apache.axis2.context.MessageContext axis2 =
                ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        try {
            Map<String, Object> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            if (askToSignIn) {
                headers.put("WWW-Authenticate", "Bearer error=\"invalid_token\"");
            }
            axis2.setProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS, headers);
            org.apache.synapse.commons.json.JsonUtil.getNewJsonPayload(axis2, body, true, true);
            axis2.setProperty("messageType", "application/json");
            axis2.setProperty("ContentType", "application/json");
            axis2.setProperty("HTTP_SC", status);
            axis2.removeProperty("NO_ENTITY_BODY");
            messageContext.setResponse(true);
            messageContext.setTo(null);
            Axis2Sender.sendBack(messageContext);
        } catch (Exception e) {
            log.error("ID-JAG: could not answer the MCP client directly", e);
        }
        return false;
    }

    private static String jsonRpcError(MessageContext messageContext, int code, String message) {
        JsonObject error = new JsonObject();
        error.addProperty("code", code);
        error.addProperty("message", message);
        JsonObject envelope = new JsonObject();
        envelope.addProperty("jsonrpc", "2.0");
        envelope.add("id", requestId(messageContext));
        envelope.add("error", error);
        return envelope.toString();
    }

    /**
     * The JSON-RPC id of the request in flight, so the client can correlate the answer.
     *
     * <p>APIM 4.6.0's McpInitHandler stores the parsed request as an
     * {@code org.wso2.carbon.apimgt.gateway.mcp.request.McpRequest} object, not as JSON text. Its
     * {@code getId()} is called reflectively: that package need not be visible to this bundle.
     */
    private static JsonElement requestId(MessageContext messageContext) {
        Object raw = messageContext.getProperty(APIMgtGatewayConstants.MCP_REQUEST_BODY);
        if (raw == null) {
            return JsonNull.INSTANCE;
        }
        try {
            return jsonRpcId(raw.getClass().getMethod("getId").invoke(raw));
        } catch (ReflectiveOperationException | RuntimeException notAnMcpRequest) {
            try {
                JsonElement id = JsonParser.parseString(raw.toString()).getAsJsonObject().get("id");
                return id == null ? JsonNull.INSTANCE : id;
            } catch (RuntimeException e) {
                return JsonNull.INSTANCE;
            }
        }
    }

    /** The tool being called, from APIM's parsed request ({@code McpRequest.getParams().getToolName()}). */
    private static String toolName(MessageContext messageContext) {
        Object raw = messageContext.getProperty(APIMgtGatewayConstants.MCP_REQUEST_BODY);
        try {
            Object params = raw.getClass().getMethod("getParams").invoke(raw);
            Object name = params.getClass().getMethod("getToolName").invoke(params);
            return name == null ? "?" : name.toString();
        } catch (ReflectiveOperationException | RuntimeException e) {
            return "?";
        }
    }

    /** A JSON-RPC id as the client sent it: Gson reads every number as a double, so 7 comes back 7.0. */
    static JsonElement jsonRpcId(Object id) {
        if (id == null) {
            return JsonNull.INSTANCE;
        }
        if (id instanceof Number n) {
            double d = n.doubleValue();
            return d == Math.rint(d) && !Double.isInfinite(d)
                    ? new JsonPrimitive(n.longValue()) : new JsonPrimitive(n);
        }
        return new JsonPrimitive(id.toString());
    }

    private IdJagExchange exchange() {
        IdJagExchange current = exchange;
        if (current == null) {
            synchronized (this) {
                current = exchange;
                if (current == null) {
                    current = new IdJagExchange(new IdJagExchange.Settings(
                            idpTokenEndpoint,
                            new IdJagExchange.Client(idpClientId, idpClientSecret,
                                    "client_secret_basic".equals(idpClientAuthMethod)),
                            audience, idpScopes,
                            resourceAsTokenEndpoint,
                            new IdJagExchange.Client(resourceAsClientId, resourceAsClientSecret,
                                    "client_secret_basic".equals(resourceAsClientAuthMethod)),
                            resourceAsScopes,
                            Duration.ofMillis(timeoutMillis), tlsInsecureSkipVerify));
                    exchange = current;
                }
            }
        }
        return current;
    }

    // --- Synapse property setters --------------------------------------------------------------

    public void setIdpTokenEndpoint(String v) { idpTokenEndpoint = v; }
    public void setIdpClientId(String v) { idpClientId = v; }
    public void setIdpClientSecret(String v) { idpClientSecret = v; }
    public void setIdpClientAuthMethod(String v) { idpClientAuthMethod = v; }
    public void setAudience(String v) { audience = v; }
    public void setIdpScopes(String v) { idpScopes = v; }
    public void setResourceAsTokenEndpoint(String v) { resourceAsTokenEndpoint = v; }
    public void setResourceAsClientId(String v) { resourceAsClientId = v; }
    public void setResourceAsClientSecret(String v) { resourceAsClientSecret = v; }
    public void setResourceAsClientAuthMethod(String v) { resourceAsClientAuthMethod = v; }
    public void setResourceAsScopes(String v) { resourceAsScopes = v; }
    public void setIdTokenHeader(String v) { idTokenHeader = v; }
    public void setHeaderName(String v) { headerName = v; }
    public void setValuePrefix(String v) { valuePrefix = v; }
    public void setTimeoutMillis(int v) { timeoutMillis = v; }
    public void setTlsInsecureSkipVerify(boolean v) { tlsInsecureSkipVerify = v; }
    public void setAuthorizationServer(String v) { authorizationServer = v == null ? "" : v.trim(); }
    public void setScopesSupported(String v) { scopesSupported = v == null ? "" : v; }
}
