package org.wso2.mcpgov.idjag;

/**
 * An exchange step failed. Carries what the gateway needs to answer the MCP client.
 *
 * <p>Mirrors the Go policy's error mapping: only the IdP rejecting the user's ID token
 * ({@code invalid_grant} or {@code interaction_required} in step 1) is a 401, which makes the
 * client sign in again. Everything else is a 502: trust or configuration the user cannot fix,
 * where a 401 would only send the client round a sign-in loop.
 *
 * <p>One addition: an expired or malformed ID token is a 401 too, decided before the IdP is
 * called, because WSO2 IS reports those as {@code invalid_request}.
 */
public class ExchangeException extends Exception {

    private final int step;
    private final String oauthError;
    private final boolean reauthenticate;

    public ExchangeException(int step, String oauthError, String message, boolean reauthenticate) {
        super(message);
        this.step = step;
        this.oauthError = oauthError;
        this.reauthenticate = reauthenticate;
    }

    /** 1 = token exchange at the IdP, 2 = jwt-bearer at the resource's authorization server. */
    public int step() {
        return step;
    }

    /** The OAuth {@code error} code from the response, if there was one. */
    public String oauthError() {
        return oauthError;
    }

    public boolean reauthenticate() {
        return reauthenticate;
    }

    public int httpStatus() {
        return reauthenticate ? 401 : 502;
    }
}
