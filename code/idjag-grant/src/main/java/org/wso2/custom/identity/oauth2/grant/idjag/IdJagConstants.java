/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.custom.identity.oauth2.grant.idjag;

/**
 * Constants used by the ID-JAG token exchange flow.
 */
public final class IdJagConstants {

    private IdJagConstants() {

    }

    /* ---------------------------------------------------------------------------------------------------------
     * Grant type and token type URNs.
     * --------------------------------------------------------------------------------------------------------- */

    public static final String TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";

    /**
     * The token type identifying an Identity Assertion JWT Authorization Grant.
     */
    public static final String ID_JAG_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id-jag";

    /**
     * Subject token types this handler implements, of the three the draft allows (ID token, SAML 2.0 assertion,
     * refresh token). SAML 2.0 is not implemented.
     */
    public static final String ID_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token";
    public static final String REFRESH_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:refresh_token";

    /**
     * Not permitted by the draft as ID-JAG subject tokens. Accepted only while
     * {@link #CONFIG_ALLOW_ACCESS_TOKEN_SUBJECT_TOKEN} is enabled, for clients written against the earlier behaviour
     * of this extension.
     */
    public static final String JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";
    public static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

    /* ---------------------------------------------------------------------------------------------------------
     * Token endpoint request parameters.
     * --------------------------------------------------------------------------------------------------------- */

    public static final String REQUESTED_TOKEN_TYPE = "requested_token_type";
    public static final String SUBJECT_TOKEN = "subject_token";
    public static final String SUBJECT_TOKEN_TYPE = "subject_token_type";

    /**
     * REQUIRED by the draft: the identifier of the resource authorization server the ID-JAG is for. Becomes "aud".
     */
    public static final String AUDIENCE = "audience";

    /**
     * OPTIONAL in the draft: an RFC 8707 resource indicator for the resource server itself. Becomes "resource".
     */
    public static final String RESOURCE = "resource";
    public static final String SCOPE = "scope";

    /* ---------------------------------------------------------------------------------------------------------
     * Token endpoint response parameters.
     * --------------------------------------------------------------------------------------------------------- */

    public static final String ISSUED_TOKEN_TYPE = "issued_token_type";

    /**
     * An ID-JAG is not an access token, so RFC 8693 token_type is reported as "N_A".
     */
    public static final String TOKEN_TYPE_NOT_APPLICABLE = "N_A";

    /* ---------------------------------------------------------------------------------------------------------
     * ID-JAG JWT header and claims.
     * --------------------------------------------------------------------------------------------------------- */

    /**
     * Mandatory value of the "typ" JOSE header of an ID-JAG.
     */
    public static final String ID_JAG_JWT_TYPE = "oauth-id-jag+jwt";

    public static final String CLIENT_ID_CLAIM = "client_id";
    public static final String SCOPE_CLAIM = "scope";
    public static final String EMAIL_CLAIM = "email";
    public static final String RESOURCE_CLAIM = "resource";

    /* ---------------------------------------------------------------------------------------------------------
     * Message context properties (per-request state; grant handlers are singletons).
     * --------------------------------------------------------------------------------------------------------- */

    public static final String PROP_ID_JAG_REQUEST = "IDJAG_REQUEST";
    /** The resolved "aud" claim value. */
    public static final String PROP_ID_JAG_AUDIENCE = "IDJAG_AUDIENCE";
    /** The client-supplied "resource" parameter, after validation; absent when the client sent none. */
    public static final String PROP_ID_JAG_RESOURCE = "IDJAG_RESOURCE";
    public static final String PROP_ID_JAG_SUBJECT_CLAIMS = "IDJAG_SUBJECT_CLAIMS";

    /* ---------------------------------------------------------------------------------------------------------
     * identity.xml configuration paths (scripts/install.sh adds the identity.xml.j2 block and the deployment.toml keys).
     * --------------------------------------------------------------------------------------------------------- */

    public static final String CONFIG_SUBJECT_CLAIM_URI = "OAuth.IDJAG.SubjectClaimUri";
    public static final String CONFIG_VALIDITY_PERIOD = "OAuth.IDJAG.ValidityPeriodInSeconds";
    public static final String CONFIG_IAT_VALIDITY_PERIOD = "OAuth.IDJAG.IATValidityPeriodInMinutes";
    public static final String CONFIG_ALLOWED_AUDIENCES = "OAuth.IDJAG.AllowedAudiences";
    public static final String CONFIG_REQUIRE_SUBJECT_CLAIM = "OAuth.IDJAG.RequireSubjectClaim";
    public static final String CONFIG_ISSUER = "OAuth.IDJAG.Issuer";
    public static final String CONFIG_AUDIENCE = "OAuth.IDJAG.Audience";
    public static final String CONFIG_FORCE_AUDIENCE = "OAuth.IDJAG.ForceAudience";
    public static final String CONFIG_CLIENT_ID = "OAuth.IDJAG.ClientId";
    public static final String CONFIG_USE_APP_CLIENT_ID = "OAuth.IDJAG.UseAppClientId";
    public static final String CONFIG_ADDITIONAL_CLAIMS = "OAuth.IDJAG.AdditionalClaims";
    public static final String CONFIG_STATIC_CLAIMS = "OAuth.IDJAG.StaticClaims";
    public static final String CONFIG_RESOURCE = "OAuth.IDJAG.Resource";
    public static final String CONFIG_ALLOW_ACCESS_TOKEN_SUBJECT_TOKEN = "OAuth.IDJAG.AllowAccessTokenSubjectToken";
    public static final String CONFIG_ALLOW_REFRESH_TOKEN_SUBJECT_TOKEN = "OAuth.IDJAG.AllowRefreshTokenSubjectToken";

    /**
     * Local claim URI carrying the user's email address; the ID-JAG "sub" is taken from this claim.
     */
    public static final String DEFAULT_SUBJECT_CLAIM_URI = "http://wso2.org/claims/emailaddress";

    public static final long DEFAULT_VALIDITY_PERIOD_SECONDS = 300L;
    public static final int DEFAULT_IAT_VALIDITY_PERIOD_MINUTES = 60;

    /* ---------------------------------------------------------------------------------------------------------
     * Misc.
     * --------------------------------------------------------------------------------------------------------- */

    /**
     * Name the resident (local) identity provider is registered under.
     */
    public static final String LOCAL_IDP_NAME = "LOCAL";

    public static final String INVALID_TARGET_ERROR_CODE = "invalid_target";
    public static final String INVALID_SCOPE_ERROR_CODE = "invalid_scope";

    /**
     * Token binding reference a refresh token carries when it is not bound to anything.
     */
    public static final String TOKEN_BINDING_NONE = "NONE";

    /**
     * A refresh token with less remaining lifetime than this is treated as expired, matching the stock refresh grant.
     */
    public static final long REFRESH_TOKEN_MINIMUM_REMAINING_MILLIS = 1000L;

    public static final String OPENID_SCOPE = "openid";
}
