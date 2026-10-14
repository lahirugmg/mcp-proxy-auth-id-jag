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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Reads the ID-JAG configuration from identity.xml (fed from deployment.toml). Every setting is optional and has a
 * usable default, so the extension works with nothing configured beyond the grant handler class itself.
 */
final class IdJagConfig {

    private static final Log log = LogFactory.getLog(IdJagConfig.class);

    private IdJagConfig() {

    }

    /**
     * Local claim URI whose value becomes the ID-JAG "sub" claim. Defaults to the email address claim, which is the
     * identifier downstream authorization servers are expected to key on.
     */
    static String getSubjectClaimUri() {

        String configured = IdentityUtil.getProperty(IdJagConstants.CONFIG_SUBJECT_CLAIM_URI);
        return StringUtils.isNotBlank(configured) ? configured.trim() : IdJagConstants.DEFAULT_SUBJECT_CLAIM_URI;
    }

    /**
     * ID-JAG lifetime in seconds. The grant is a single-use credential presented immediately to the resource
     * application's token endpoint, so the default is deliberately short.
     */
    static long getValidityPeriodInSeconds() {

        String configured = IdentityUtil.getProperty(IdJagConstants.CONFIG_VALIDITY_PERIOD);
        if (StringUtils.isBlank(configured)) {
            return IdJagConstants.DEFAULT_VALIDITY_PERIOD_SECONDS;
        }
        try {
            long value = Long.parseLong(configured.trim());
            if (value <= 0) {
                log.warn("Ignoring non-positive " + IdJagConstants.CONFIG_VALIDITY_PERIOD + " value: " + configured
                        + ". Falling back to " + IdJagConstants.DEFAULT_VALIDITY_PERIOD_SECONDS + " seconds.");
                return IdJagConstants.DEFAULT_VALIDITY_PERIOD_SECONDS;
            }
            return value;
        } catch (NumberFormatException e) {
            log.warn("Ignoring malformed " + IdJagConstants.CONFIG_VALIDITY_PERIOD + " value: " + configured
                    + ". Falling back to " + IdJagConstants.DEFAULT_VALIDITY_PERIOD_SECONDS + " seconds.");
            return IdJagConstants.DEFAULT_VALIDITY_PERIOD_SECONDS;
        }
    }

    /**
     * How old the subject token's "iat" may be before it is rejected.
     */
    static int getIatValidityPeriodInMinutes() {

        String configured = IdentityUtil.getProperty(IdJagConstants.CONFIG_IAT_VALIDITY_PERIOD);
        if (StringUtils.isBlank(configured)) {
            return IdJagConstants.DEFAULT_IAT_VALIDITY_PERIOD_MINUTES;
        }
        try {
            return Integer.parseInt(configured.trim());
        } catch (NumberFormatException e) {
            log.warn("Ignoring malformed " + IdJagConstants.CONFIG_IAT_VALIDITY_PERIOD + " value: " + configured
                    + ". Falling back to " + IdJagConstants.DEFAULT_IAT_VALIDITY_PERIOD_MINUTES + " minutes.");
            return IdJagConstants.DEFAULT_IAT_VALIDITY_PERIOD_MINUTES;
        }
    }

    /**
     * Value for the ID-JAG {@code iss} claim. Blank means use this server's own OpenID Connect token issuer, which is
     * the right answer whenever the resource application validates the grant against this server's published
     * metadata. Override it when the third party knows this identity provider by some other issuer identifier -- a
     * public URL in front of a private deployment, for instance.
     */
    static String getIssuer() {

        String configured = IdentityUtil.getProperty(IdJagConstants.CONFIG_ISSUER);
        return StringUtils.isBlank(configured) ? null : configured.trim();
    }

    /**
     * Server-configured value for the ID-JAG {@code aud} claim: the issuer URL of the resource application's
     * authorization server. Blank means the target comes from the request's {@code resource} parameter, as the
     * specification intends. When set, it supplies the target for requests that omit {@code resource}, and -- if
     * {@link #isAudienceForced()} is also on -- replaces any target the client does send.
     */
    static String getAudience() {

        String configured = IdentityUtil.getProperty(IdJagConstants.CONFIG_AUDIENCE);
        return StringUtils.isBlank(configured) ? null : configured.trim();
    }

    /**
     * Whether the configured audience replaces a client-supplied {@code resource} rather than merely defaulting it.
     * Off by default: silently retargeting a grant the client asked to have minted for somewhere else is a
     * surprising thing for a server to do, so it has to be asked for.
     */
    static boolean isAudienceForced() {

        return Boolean.parseBoolean(
                StringUtils.trimToEmpty(IdentityUtil.getProperty(IdJagConstants.CONFIG_FORCE_AUDIENCE)));
    }

    /**
     * Value for the ID-JAG {@code client_id} claim. The draft requires an identifier the resource application's
     * authorization server recognises, which is generally not the identifier the client used here: the client is
     * registered separately at each end. Blank means emit the requesting client's own id, which is right only when
     * both sides know it by the same name.
     */
    static String getClientId() {

        String configured = IdentityUtil.getProperty(IdJagConstants.CONFIG_CLIENT_ID);
        return StringUtils.isBlank(configured) ? null : configured.trim();
    }

    /**
     * When true, the ID-JAG {@code client_id} claim is always the requesting application's own client id at this
     * server, and {@link #getClientId()} is ignored. This is for deployments that register each application at the
     * resource authorization server and create the matching IS application with that same client id, so one static
     * override would be wrong for all but one of them. Off by default.
     */
    static boolean isAppClientIdUsed() {

        return Boolean.parseBoolean(
                StringUtils.trimToEmpty(IdentityUtil.getProperty(IdJagConstants.CONFIG_USE_APP_CLIENT_ID)));
    }

    /**
     * Resolves the value of the ID-JAG {@code client_id} claim for a request from {@code requestingClientId}.
     * The draft requires the identifier the resource authorization server knows the client by. Order: the
     * application's own id when {@link #isAppClientIdUsed()} is on, else the configured override, else the
     * application's own id.
     */
    static String resolveClientIdClaim(String requestingClientId) {

        if (isAppClientIdUsed()) {
            return requestingClientId;
        }
        String configured = getClientId();
        return configured != null ? configured : requestingClientId;
    }

    /**
     * Value for the ID-JAG {@code resource} claim: the protected resource the grant is to be spent at, as distinct
     * from {@code aud}, which names the authorization server that issues the access token for it.
     * <p>
     * Blank means the claim carries the request's {@code resource} parameter, or is omitted when the client sent
     * none. When set it replaces whatever the client asked for. Set this when the resource application identifies
     * its resources by something the client cannot know or would get wrong.
     */
    static String getResource() {

        String configured = IdentityUtil.getProperty(IdJagConstants.CONFIG_RESOURCE);
        return StringUtils.isBlank(configured) ? null : configured.trim();
    }

    /**
     * Extra user claims to carry in the ID-JAG, configured as a comma separated list of
     * {@code claimName=localClaimUri} pairs, for example
     * {@code emailVerified=http://wso2.org/claims/identity/emailVerified}. The left side is the claim name as it
     * appears in the JWT, the right side the local claim to read the value from. Split on the first {@code =} only,
     * since claim URIs contain no {@code =} but do contain {@code :}.
     * <p>
     * A claim with no value for the user is omitted rather than emitted empty.
     */
    static Map<String, String> getAdditionalClaims() {

        String configured = IdentityUtil.getProperty(IdJagConstants.CONFIG_ADDITIONAL_CLAIMS);
        if (StringUtils.isBlank(configured)) {
            return Collections.emptyMap();
        }
        Map<String, String> claims = new LinkedHashMap<>();
        for (String pair : configured.split(",")) {
            if (StringUtils.isBlank(pair)) {
                continue;
            }
            int split = pair.indexOf('=');
            if (split <= 0 || split == pair.trim().length() - 1) {
                log.warn("Ignoring malformed " + IdJagConstants.CONFIG_ADDITIONAL_CLAIMS + " entry: '" + pair.trim()
                        + "'. Expected claimName=localClaimUri.");
                continue;
            }
            String name = pair.substring(0, split).trim();
            String uri = pair.substring(split + 1).trim();
            if (StringUtils.isBlank(name) || StringUtils.isBlank(uri)) {
                log.warn("Ignoring malformed " + IdJagConstants.CONFIG_ADDITIONAL_CLAIMS + " entry: '" + pair.trim()
                        + "'. Expected claimName=localClaimUri.");
                continue;
            }
            claims.put(name, uri);
        }
        return claims;
    }

    /**
     * Fixed claims to carry in every ID-JAG, configured as comma separated {@code claimName=value} pairs, for
     * example {@code aud_tenant=f75bde08-df24-4a20-8928-21105007b40b}. For values that describe the resource
     * application rather than the user, such as the draft's {@code aud_tenant}: the tenant at the resource
     * authorization server (Atlassian's cloud id). Values "true"/"false" are emitted as JSON booleans.
     * <p>
     * Registered claims ({@code iss}, {@code sub}, {@code aud}, {@code client_id}, {@code iat}, {@code exp},
     * {@code jti}) cannot be set this way; they have their own keys or are computed.
     */
    static Map<String, String> getStaticClaims() {

        String configured = IdentityUtil.getProperty(IdJagConstants.CONFIG_STATIC_CLAIMS);
        if (StringUtils.isBlank(configured)) {
            return Collections.emptyMap();
        }
        Map<String, String> claims = new LinkedHashMap<>();
        for (String pair : configured.split(",")) {
            if (StringUtils.isBlank(pair)) {
                continue;
            }
            int split = pair.indexOf('=');
            String name = split <= 0 ? "" : pair.substring(0, split).trim();
            String value = split <= 0 ? "" : pair.substring(split + 1).trim();
            if (StringUtils.isBlank(name) || StringUtils.isBlank(value) || RESERVED_CLAIMS.contains(name)) {
                log.warn("Ignoring " + IdJagConstants.CONFIG_STATIC_CLAIMS + " entry: '" + pair.trim()
                        + "'. Expected claimName=value, and not a registered claim.");
                continue;
            }
            claims.put(name, value);
        }
        return claims;
    }

    private static final java.util.Set<String> RESERVED_CLAIMS = new java.util.HashSet<>(java.util.Arrays.asList(
            "iss", "sub", "aud", "client_id", "iat", "exp", "nbf", "jti"));

    /**
     * Comma separated allowlist of resource authorization server issuers an ID-JAG may be minted for. This is the
     * minimum viable stand-in for the admin policy the specification expects the IdP to evaluate. An empty
     * configuration allows any audience, which is convenient while integrating but should be populated before the
     * deployment is exposed to untrusted clients.
     */
    static Set<String> getAllowedAudiences() {

        String configured = IdentityUtil.getProperty(IdJagConstants.CONFIG_ALLOWED_AUDIENCES);
        if (StringUtils.isBlank(configured)) {
            return Collections.emptySet();
        }
        return Arrays.stream(configured.split(","))
                .map(String::trim)
                .filter(StringUtils::isNotBlank)
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    /**
     * Whether an access token (or a bare JWT) may be presented as the ID-JAG subject token. The draft permits only an
     * identity assertion (ID token or SAML 2.0 assertion) or a refresh token, so this is off by default. It exists for
     * clients built against an earlier version of this extension, which accepted access tokens, and is meant to be
     * switched off again once those clients present ID tokens.
     */
    static boolean isAccessTokenSubjectTokenAllowed() {

        return Boolean.parseBoolean(StringUtils.trimToEmpty(
                IdentityUtil.getProperty(IdJagConstants.CONFIG_ALLOW_ACCESS_TOKEN_SUBJECT_TOKEN)));
    }

    /**
     * Whether a refresh token issued by this server may be presented as the ID-JAG subject token. The draft permits
     * this "when supported by the IdP Authorization Server", so it is on by default and can be switched off by
     * deployments that want an ID-JAG to require a live ID token.
     */
    static boolean isRefreshTokenSubjectTokenAllowed() {

        String configured = IdentityUtil.getProperty(IdJagConstants.CONFIG_ALLOW_REFRESH_TOKEN_SUBJECT_TOKEN);
        return StringUtils.isBlank(configured) || Boolean.parseBoolean(configured.trim());
    }

    /**
     * Whether a missing subject claim (e.g. a user with no email address) fails the request. Enabled by default: an
     * ID-JAG whose "sub" silently fell back to the subject UUID would be accepted by the resource application and
     * mapped to the wrong account, so failing closed is the safer behaviour.
     */
    static boolean isSubjectClaimRequired() {

        String configured = IdentityUtil.getProperty(IdJagConstants.CONFIG_REQUIRE_SUBJECT_CLAIM);
        return StringUtils.isBlank(configured) || Boolean.parseBoolean(configured.trim());
    }
}
