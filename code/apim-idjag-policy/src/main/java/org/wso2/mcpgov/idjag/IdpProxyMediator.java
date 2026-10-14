package org.wso2.mcpgov.idjag;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext;
import org.apache.synapse.commons.json.JsonUtil;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.mediators.AbstractMediator;
import org.apache.synapse.transport.passthru.util.RelayUtils;

import java.net.URI;

/**
 * The response flow of the gateway's {@code /idp} API, which relays two WSO2 IS endpoints to the
 * MCP client (GitHub Copilot in VS Code) so that the gateway sees every token response:
 *
 * <pre>
 *   GET  /idp/oauth2/token/.well-known/openid-configuration
 *        IS's sign-in metadata, with token_endpoint pointed at the gateway and
 *        registration_endpoint removed (the client uses its pre-registered client ID)
 *   POST /idp/oauth2/token
 *        IS's token response, unchanged; its id_token is kept in {@link IdTokenStore}
 * </pre>
 *
 * <p>Sign-in itself ({@code authorization_endpoint}) stays at IS: the user's browser talks to IS
 * directly, and only the code-for-token and refresh calls pass through the gateway.
 *
 * <p>Rendered by the custom policy {@code idpProxy}, attached to the {@code /idp} API's response
 * flow. The response body is IS's, so the ID token kept here was issued by IS to this request.
 */
public class IdpProxyMediator extends AbstractMediator {

    private static final Log log = LogFactory.getLog(IdpProxyMediator.class);

    // --- Synapse properties (set from the policy) ----------------------------------------------
    /** The gateway's address for IS, e.g. {@code https://localhost:8243/idp}. */
    private String publicBaseUrl;

    private final IdTokenStore store;

    public IdpProxyMediator() {
        this(IdTokenStore.shared());
    }

    IdpProxyMediator(IdTokenStore store) {
        this.store = store;
    }

    @Override
    public boolean mediate(MessageContext messageContext) {
        org.apache.axis2.context.MessageContext axis2 =
                ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        Object status = axis2.getProperty("HTTP_SC");
        if (status != null && !"200".equals(status.toString())) {
            return true; // IS's errors go back as they are
        }
        JsonObject body;
        try {
            RelayUtils.buildMessage(axis2); // the pass-through transport has not read the body yet
            if (!JsonUtil.hasAJsonPayload(axis2)) {
                return true;
            }
            JsonElement parsed = JsonParser.parseString(JsonUtil.jsonPayloadToString(axis2));
            if (!parsed.isJsonObject()) {
                return true;
            }
            body = parsed.getAsJsonObject();
        } catch (Exception e) {
            log.warn("ID-JAG: could not read the IS response: " + e.getMessage());
            return true;
        }

        if (body.has("id_token")) {
            String sub = keepIdToken(body, store);
            if (sub != null) {
                log.info("ID-JAG: kept the ID token for " + sub);
            } else {
                log.warn("ID-JAG: the token response carried an ID token that could not be kept");
            }
        } else if (body.has("token_endpoint")) {
            try {
                JsonUtil.getNewJsonPayload(axis2, rewriteMetadata(body, publicBaseUrl).toString(), true, true);
            } catch (Exception e) {
                log.error("ID-JAG: could not rewrite IS's metadata", e);
            }
        }
        return true;
    }

    /** Keep a token response's {@code id_token}; returns its {@code sub}, or null. */
    static String keepIdToken(JsonObject tokenResponse, IdTokenStore store) {
        JsonElement idToken = tokenResponse.get("id_token");
        return idToken != null && idToken.isJsonPrimitive() ? store.put(idToken.getAsString()) : null;
    }

    /**
     * IS's metadata as the MCP client should see it: tokens are fetched and refreshed through the
     * gateway, and dynamic registration is not offered.
     */
    static JsonObject rewriteMetadata(JsonObject metadata, String publicBaseUrl) {
        JsonObject rewritten = metadata.deepCopy();
        String path = URI.create(metadata.get("token_endpoint").getAsString()).getRawPath();
        rewritten.addProperty("token_endpoint", stripTrailingSlash(publicBaseUrl) + path);
        rewritten.remove("registration_endpoint");
        return rewritten;
    }

    private static String stripTrailingSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    public void setPublicBaseUrl(String v) { publicBaseUrl = v; }
}
