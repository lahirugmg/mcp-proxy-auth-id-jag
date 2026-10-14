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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.tokenprocessor.HybridRefreshTokenGrantProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.RefreshTokenGrantProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.grant.token.exchange.TokenExchangeGrantHandler;
import org.wso2.carbon.identity.oauth2.grant.token.exchange.utils.TokenExchangeUtils;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.JWTUtils;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.util.TokenMgtUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Token exchange grant handler that adds support for issuing Identity Assertion JWT Authorization Grants (ID-JAG) as
 * described in draft-ietf-oauth-identity-assertion-authz-grant.
 * <p>
 * This handler serves the "identity provider issues an ID-JAG" use case: a client that has already authenticated a
 * user against this Identity Server presents the resulting ID token as {@code subject_token} and receives a signed
 * {@code oauth-id-jag+jwt} addressed to a third party authorization server that trusts this server. The client then
 * presents that JWT to the third party's token endpoint over the JWT bearer grant.
 * <p>
 * A request is treated as an ID-JAG request when {@code requested_token_type} is
 * {@value IdJagConstants#ID_JAG_TOKEN_TYPE}. Every other token exchange request is delegated unchanged to
 * {@link TokenExchangeGrantHandler}, so replacing the stock handler with this one does not alter existing token
 * exchange or impersonation behaviour.
 * <p>
 * The ID-JAG {@code sub} claim carries the user's email address rather than the subject UUID the server would
 * otherwise use, because the third party authorization server identifies the resource owner by email. See
 * {@link IdJagSubjectResolver}.
 */
public class IdJagGrantHandler extends TokenExchangeGrantHandler {

    private static final Log log = LogFactory.getLog(IdJagGrantHandler.class);

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        Map<String, String> requestParams = toRequestParamMap(tokReqMsgCtx);
        if (!IdJagConstants.ID_JAG_TOKEN_TYPE.equals(requestParams.get(IdJagConstants.REQUESTED_TOKEN_TYPE))) {
            return super.validateGrant(tokReqMsgCtx);
        }

        // Flag the request so the remaining lifecycle methods take the ID-JAG path. Grant handlers are singletons
        // shared across concurrent requests, so this state must live on the message context, never on the handler.
        tokReqMsgCtx.addProperty(IdJagConstants.PROP_ID_JAG_REQUEST, Boolean.TRUE);
        return validateIdJagGrant(tokReqMsgCtx, requestParams);
    }

    /**
     * Validates an ID-JAG request: the target authorization server, the optional resource indicator, the subject
     * token, and the resource owner it asserts.
     */
    private boolean validateIdJagGrant(OAuthTokenReqMessageContext tokReqMsgCtx, Map<String, String> requestParams)
            throws IdentityOAuth2Exception {

        OAuth2AccessTokenReqDTO tokenReqDTO = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
        String clientId = tokenReqDTO.getClientId();
        String tenantDomain = resolveTenantDomain(tokenReqDTO);

        String audience = resolveTargetAudience(requestParams);
        tokReqMsgCtx.addProperty(IdJagConstants.PROP_ID_JAG_AUDIENCE, audience);

        String resource = resolveRequestedResource(requestParams);
        if (resource != null) {
            tokReqMsgCtx.addProperty(IdJagConstants.PROP_ID_JAG_RESOURCE, resource);
        }

        // "openid" is dropped from the requested scopes: it is an OpenID Connect request marker for this server, not
        // an authority at the resource application, and if it survives validation AccessTokenIssuer attaches an ID
        // token to the token exchange response, which an ID-JAG response must not carry.
        String[] requestedScopes = withoutOpenIdScope(tokenReqDTO.getScope());

        if (IdJagConstants.REFRESH_TOKEN_TYPE.equals(requestParams.get(IdJagConstants.SUBJECT_TOKEN_TYPE))) {
            // A refresh token is looked up, not parsed: the user and the authorised scopes come from the token
            // record, and the requested scopes may only narrow them.
            requestedScopes = validateRefreshTokenSubject(tokReqMsgCtx, requestParams, clientId, requestedScopes);
        } else {
            JWTClaimsSet subjectClaims = validateSubjectToken(tokReqMsgCtx, requestParams, tenantDomain, clientId);
            tokReqMsgCtx.addProperty(IdJagConstants.PROP_ID_JAG_SUBJECT_CLAIMS, subjectClaims);
        }

        // Seed the scopes so the framework can validate them. The message context does not inherit them from the
        // request, and AccessTokenIssuer reads them from here. What survives validation is whatever the user's roles
        // and the application's authorised API resources permit -- the same treatment an access token gets. This
        // handler deliberately does not second-guess that result.
        tokReqMsgCtx.setScope(requestedScopes);

        if (log.isDebugEnabled()) {
            log.debug("Validated ID-JAG request from client: " + clientId + " for audience: " + audience
                    + (resource == null ? "" : " and resource: " + resource) + " in tenant: " + tenantDomain);
        }
        return true;
    }

    /**
     * Determines the {@code aud} of the ID-JAG: the identifier of the resource application's authorization server.
     * <p>
     * The draft makes the {@code audience} request parameter REQUIRED for this. A deployment can instead pin it with
     * {@code oauth.idjag.audience}, which then serves requests that omit {@code audience} and, with
     * {@code oauth.idjag.force_audience} enabled, overrides whatever the client asked for.
     * <p>
     * The allowlist is only consulted for a client-supplied target. An administrator who configured the audience has
     * already made that decision.
     */
    private String resolveTargetAudience(Map<String, String> requestParams) throws IdentityOAuth2Exception {

        String requested = requestParams.get(IdJagConstants.AUDIENCE);
        String configured = IdJagConfig.getAudience();

        String target;
        boolean administrativelySet;
        if (configured != null && (IdJagConfig.isAudienceForced() || StringUtils.isBlank(requested))) {
            if (StringUtils.isNotBlank(requested) && !configured.equals(requested)) {
                // Worth a warning rather than a debug line: in steady state a client should not be asking for a
                // target the server is configured to overrule.
                log.warn("Overriding the requested ID-JAG target '" + requested + "' with the configured "
                        + IdJagConstants.CONFIG_AUDIENCE + " '" + configured + "'.");
            }
            target = configured;
            administrativelySet = true;
        } else if (StringUtils.isNotBlank(requested)) {
            target = requested;
            administrativelySet = false;
        } else {
            throw new IdentityOAuth2ClientException(OAuth2ErrorCodes.INVALID_REQUEST,
                    "Parameter 'audience' is required when requesting an ID-JAG. It must carry the identifier of "
                            + "the resource application's authorization server. Alternatively, configure "
                            + "oauth.idjag.audience to supply it server side.");
        }

        if (!administrativelySet) {
            // Only a client-supplied target has to look like a URI. A configured one is whatever the third party
            // says it is -- some authorization servers identify themselves with an opaque id rather than their
            // issuer URL -- so the administrator's value is taken as given.
            validateAbsoluteUri(IdJagConstants.AUDIENCE, target);
            validateAllowedAudience(target);
        }
        return target;
    }

    /**
     * The optional {@code resource} request parameter: an RFC 8707 resource indicator naming the resource server the
     * grant will be spent at, as distinct from the authorization server that redeems it. It is validated when present
     * and carried into the {@code resource} claim unless {@code oauth.idjag.resource} overrides it.
     *
     * @return the validated resource indicator, or null when the client sent none.
     */
    private String resolveRequestedResource(Map<String, String> requestParams) throws IdentityOAuth2Exception {

        String requested = requestParams.get(IdJagConstants.RESOURCE);
        if (StringUtils.isBlank(requested)) {
            return null;
        }
        validateAbsoluteUri(IdJagConstants.RESOURCE, requested);
        return requested;
    }

    /**
     * Both the authorization server identifier and an RFC 8707 resource indicator are absolute URIs without a
     * fragment component.
     */
    private void validateAbsoluteUri(String parameterName, String value) throws IdentityOAuth2Exception {

        try {
            URI uri = new URI(value);
            if (!uri.isAbsolute() || StringUtils.isNotBlank(uri.getFragment())) {
                throw new IdentityOAuth2ClientException(IdJagConstants.INVALID_TARGET_ERROR_CODE,
                        "Parameter '" + parameterName + "' must be an absolute URI without a fragment component. "
                                + "Received: " + value);
            }
        } catch (URISyntaxException e) {
            throw new IdentityOAuth2ClientException(IdJagConstants.INVALID_TARGET_ERROR_CODE,
                    "Parameter '" + parameterName + "' is not a valid URI: " + value, e);
        }
    }

    /**
     * Enforces the configured allowlist of resource authorization servers. Extension point: override this to consult
     * a real policy store keyed on client, user and target.
     */
    protected void validateAllowedAudience(String audience) throws IdentityOAuth2Exception {

        Set<String> allowedAudiences = IdJagConfig.getAllowedAudiences();
        if (allowedAudiences.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("No ID-JAG audience allowlist is configured (" + IdJagConstants.CONFIG_ALLOWED_AUDIENCES
                        + "), so an ID-JAG may be issued for any audience. Requested audience: " + audience);
            }
            return;
        }
        if (!allowedAudiences.contains(audience)) {
            throw new IdentityOAuth2ClientException(IdJagConstants.INVALID_TARGET_ERROR_CODE,
                    "The requested audience is not an allowed ID-JAG audience: " + audience);
        }
    }

    /**
     * Validates the presented identity assertion and binds the resulting resource owner to the message context.
     *
     * @return the claims of the validated subject token.
     */
    private JWTClaimsSet validateSubjectToken(OAuthTokenReqMessageContext tokReqMsgCtx,
                                              Map<String, String> requestParams, String tenantDomain, String clientId)
            throws IdentityOAuth2Exception {

        String subjectTokenType = requestParams.get(IdJagConstants.SUBJECT_TOKEN_TYPE);
        String subjectToken = requestParams.get(IdJagConstants.SUBJECT_TOKEN);
        if (StringUtils.isBlank(subjectToken)) {
            throw new IdentityOAuth2ClientException(OAuth2ErrorCodes.INVALID_REQUEST,
                    "Parameter 'subject_token' is required when requesting an ID-JAG.");
        }
        if (!isSupportedSubjectTokenType(subjectTokenType, subjectToken, clientId)) {
            throw new IdentityOAuth2ClientException(OAuth2ErrorCodes.INVALID_REQUEST,
                    "Unsupported subject_token_type for an ID-JAG request: " + subjectTokenType + ". Expected "
                            + IdJagConstants.ID_TOKEN_TYPE + " or " + IdJagConstants.REFRESH_TOKEN_TYPE + ".");
        }

        SignedJWT signedJWT = TokenExchangeUtils.getSignedJWT(subjectToken);
        if (signedJWT == null) {
            throw new IdentityOAuth2ClientException(OAuth2ErrorCodes.INVALID_REQUEST,
                    "The 'subject_token' is not a signed JWT.");
        }
        JWTClaimsSet claimsSet = TokenExchangeUtils.getClaimSet(signedJWT);
        if (claimsSet == null) {
            throw new IdentityOAuth2ClientException(OAuth2ErrorCodes.INVALID_REQUEST,
                    "The 'subject_token' carries no claims.");
        }

        String issuer = claimsSet.getIssuer();
        String subject = claimsSet.getSubject();
        if (StringUtils.isBlank(issuer) || StringUtils.isBlank(subject)) {
            throw new IdentityOAuth2ClientException(OAuth2ErrorCodes.INVALID_REQUEST,
                    "The 'subject_token' must carry both 'iss' and 'sub' claims.");
        }
        if (claimsSet.getExpirationTime() == null) {
            throw new IdentityOAuth2ClientException(OAuth2ErrorCodes.INVALID_REQUEST,
                    "The 'subject_token' must carry an 'exp' claim.");
        }

        IdentityProvider identityProvider = TokenExchangeUtils.getIDP(issuer, tenantDomain);
        try {
            if (!TokenExchangeUtils.validateSignature(signedJWT, identityProvider, tenantDomain)) {
                throw new IdentityOAuth2ClientException(OAuth2ErrorCodes.INVALID_REQUEST,
                        "Signature validation failed for the 'subject_token'.");
            }
        } catch (JOSEException e) {
            throw new IdentityOAuth2ClientException(OAuth2ErrorCodes.INVALID_REQUEST,
                    "Error while verifying the signature of the 'subject_token'.", e);
        }

        validateTokenTimestamps(claimsSet);
        validateSubjectTokenAudience(claimsSet, identityProvider, tenantDomain, clientId);
        setAuthorizedUser(tokReqMsgCtx, identityProvider, subject, claimsSet, tenantDomain, clientId);

        return claimsSet;
    }

    /**
     * Validates a refresh token presented as the subject token and binds the resource owner it was issued to.
     * <p>
     * The draft's processing rule: "the IdP MUST validate it the same way it would for a standard refresh_token grant
     * at the token endpoint: the token is issued by the IdP, bound to the authenticated client, unexpired, not
     * revoked, and the requested scopes and audience remain within the authorization context of the Refresh Token."
     * The lookup, client binding, revocation and rotation checks are delegated to the same
     * {@link RefreshTokenGrantProcessor} the stock refresh grant uses, so persisted, hybrid and JWT refresh tokens are
     * all handled the way this server handles them elsewhere. The refresh token is only read; it is not rotated or
     * consumed, so the client keeps using it.
     * <p>
     * A refresh token bound to something (a certificate, a cookie, DPoP) is rejected: the binding cannot be proven
     * through a token exchange request, and an ID-JAG minted from it would silently drop that protection.
     *
     * @return the scopes to seed for validation: the requested scopes if any, otherwise everything the refresh token
     * was issued with.
     */
    private String[] validateRefreshTokenSubject(OAuthTokenReqMessageContext tokReqMsgCtx,
                                                 Map<String, String> requestParams, String clientId,
                                                 String[] requestedScopes) throws IdentityOAuth2Exception {

        if (!IdJagConfig.isRefreshTokenSubjectTokenAllowed()) {
            throw new IdentityOAuth2ClientException(OAuth2ErrorCodes.INVALID_REQUEST,
                    "Refresh tokens are not accepted as the subject_token of an ID-JAG request on this server. "
                            + "Expected " + IdJagConstants.ID_TOKEN_TYPE + ".");
        }
        String refreshToken = requestParams.get(IdJagConstants.SUBJECT_TOKEN);
        if (StringUtils.isBlank(refreshToken)) {
            throw new IdentityOAuth2ClientException(OAuth2ErrorCodes.INVALID_REQUEST,
                    "Parameter 'subject_token' is required when requesting an ID-JAG.");
        }

        // The processors read the token from the request DTO, where the refresh grant would have put it.
        OAuth2AccessTokenReqDTO tokenReqDTO = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
        tokenReqDTO.setRefreshToken(refreshToken);

        RefreshTokenValidationDataDO tokenData;
        try {
            RefreshTokenGrantProcessor processor = resolveRefreshTokenGrantProcessor(refreshToken);
            tokenData = processor.validateRefreshToken(tokReqMsgCtx);
            if (tokenData == null || tokenData.getAuthorizedUser() == null) {
                throw new IdentityOAuth2ClientException(OAuth2ErrorCodes.INVALID_GRANT,
                        "The 'subject_token' is not a valid refresh token issued to the requesting client.");
            }
            String state = tokenData.getRefreshTokenState();
            if (state != null && !OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE.equals(state)
                    && !OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED.equals(state)) {
                // EXPIRED here is the state of the access token the refresh token was issued with; the refresh token
                // itself is still usable until its own validity runs out, which is checked below. Anything else
                // (REVOKED, INACTIVE) means the grant was withdrawn.
                throw new IdentityOAuth2ClientException(OAuth2ErrorCodes.INVALID_GRANT,
                        "The 'subject_token' refresh token has been revoked or is inactive.");
            }
            if (!processor.isLatestRefreshToken(tokenReqDTO, tokenData,
                    OAuth2Util.getUserStoreDomain(tokenData.getAuthorizedUser()))) {
                throw new IdentityOAuth2ClientException(OAuth2ErrorCodes.INVALID_GRANT,
                        "The 'subject_token' refresh token has been superseded by a newer one.");
            }
        } catch (IdentityOAuth2ClientException e) {
            throw e;
        } catch (IdentityOAuth2Exception e) {
            // The processors report an unknown token, a token of another client, and most other failures as a plain
            // IdentityOAuth2Exception. To the caller all of those are the same thing: not a grant we will honour.
            throw new IdentityOAuth2ClientException(OAuth2ErrorCodes.INVALID_GRANT,
                    "The 'subject_token' is not a valid refresh token issued to the requesting client.", e);
        }

        if (isRefreshTokenExpired(tokenData)) {
            throw new IdentityOAuth2ClientException(OAuth2ErrorCodes.INVALID_GRANT,
                    "The 'subject_token' refresh token has expired.");
        }
        String bindingReference = tokenData.getTokenBindingReference();
        if (tokenData.getTokenBinding() != null
                || (StringUtils.isNotBlank(bindingReference)
                && !IdJagConstants.TOKEN_BINDING_NONE.equals(bindingReference))) {
            String bindingType = tokenData.getTokenBinding() == null ? "unknown"
                    : tokenData.getTokenBinding().getBindingType();
            log.warn("Rejecting an ID-JAG request from client " + clientId + ": the refresh token presented as "
                    + "subject_token is bound (binding type: " + bindingType + ", reference: " + bindingReference
                    + "), and a token exchange request cannot prove that binding. Disable token binding on the "
                    + "application if its refresh tokens should be exchangeable for ID-JAGs.");
            throw new IdentityOAuth2ClientException(OAuth2ErrorCodes.INVALID_GRANT,
                    "The 'subject_token' refresh token is bound to a client context that a token exchange request "
                            + "cannot prove, so it cannot be used to obtain an ID-JAG.");
        }

        String[] grantedScopes = withoutOpenIdScope(tokenData.getScope());
        String[] scopesToSeed = narrowToGrantedScopes(requestedScopes, grantedScopes);

        tokReqMsgCtx.setAuthorizedUser(tokenData.getAuthorizedUser());
        if (log.isDebugEnabled()) {
            log.debug("Accepted a refresh token as the ID-JAG subject token for client: " + clientId + ", user: "
                    + tokenData.getAuthorizedUser().getLoggableMaskedUserId() + ", scopes: "
                    + String.join(" ", scopesToSeed));
        }
        return scopesToSeed;
    }

    /**
     * Chooses the processor the way the stock refresh grant does: the registered (persisted-token) processor when
     * tokens are persisted, otherwise the hybrid processor for JWT or hybrid-persisted refresh tokens.
     */
    private RefreshTokenGrantProcessor resolveRefreshTokenGrantProcessor(String refreshToken) {

        if (OAuth2Util.isAccessTokenPersistenceEnabled()) {
            return OAuth2ServiceComponentHolder.getInstance().getRefreshTokenGrantProcessor();
        }
        if (TokenMgtUtil.isHybridPersistedToken(refreshToken) || JWTUtils.isJWT(refreshToken)) {
            return new HybridRefreshTokenGrantProcessor();
        }
        return OAuth2ServiceComponentHolder.getInstance().getRefreshTokenGrantProcessor();
    }

    private boolean isRefreshTokenExpired(RefreshTokenValidationDataDO tokenData) {

        long validity = tokenData.getValidityPeriodInMillis();
        if (validity < 0) {
            return false;
        }
        if (tokenData.getIssuedTime() == null) {
            return true;
        }
        return OAuth2Util.getTimeToExpire(tokenData.getIssuedTime().getTime(), validity)
                < IdJagConstants.REFRESH_TOKEN_MINIMUM_REMAINING_MILLIS;
    }

    /**
     * "The requested scopes ... remain within the authorization context of the Refresh Token": a requested scope the
     * token was not issued with is a client error, not something to drop quietly. With no scopes requested the
     * token's own scopes are used, as the refresh grant does.
     */
    private String[] narrowToGrantedScopes(String[] requested, String[] granted) throws IdentityOAuth2Exception {

        if (requested == null || requested.length == 0) {
            return granted;
        }
        Set<String> grantedSet = new java.util.HashSet<>(java.util.Arrays.asList(granted));
        List<String> excess = new java.util.ArrayList<>();
        for (String scope : requested) {
            if (!grantedSet.contains(scope)) {
                excess.add(scope);
            }
        }
        if (!excess.isEmpty()) {
            throw new IdentityOAuth2ClientException(IdJagConstants.INVALID_SCOPE_ERROR_CODE,
                    "The requested scope(s) " + String.join(" ", excess) + " are not within the authorization of the "
                            + "'subject_token' refresh token.");
        }
        return requested;
    }

    /**
     * The draft allows three subject token types: an OpenID Connect ID token, a SAML 2.0 assertion, or a refresh
     * token. This handler implements the ID token here and the refresh token in
     * {@link #validateRefreshTokenSubject}. SAML 2.0 is not implemented and is rejected.
     * <p>
     * An access token (or a bare JWT) is not an identity assertion and is outside the draft. Earlier versions of this
     * extension accepted one anyway, so for clients still built that way it can be re-enabled with
     * {@code oauth.idjag.allow_access_token_subject_token}. Each such use is logged at WARN so the deployment can see
     * when the switch can be turned off again.
     */
    private boolean isSupportedSubjectTokenType(String subjectTokenType, String subjectToken, String clientId) {

        if (IdJagConstants.ID_TOKEN_TYPE.equals(subjectTokenType)) {
            return true;
        }
        boolean legacyType = IdJagConstants.JWT_TOKEN_TYPE.equals(subjectTokenType)
                || IdJagConstants.ACCESS_TOKEN_TYPE.equals(subjectTokenType);
        if (!legacyType) {
            return false;
        }
        if (!IdJagConfig.isAccessTokenSubjectTokenAllowed()) {
            if (log.isDebugEnabled()) {
                log.debug("Rejecting subject_token_type '" + subjectTokenType + "' from client " + clientId
                        + ": the ID-JAG draft does not permit access tokens as subject tokens and "
                        + IdJagConstants.CONFIG_ALLOW_ACCESS_TOKEN_SUBJECT_TOKEN + " is not enabled.");
            }
            return false;
        }
        if (!OAuth2Util.isJWT(subjectToken)) {
            return false;
        }
        log.warn("Client " + clientId + " presented subject_token_type '" + subjectTokenType + "' for an ID-JAG. "
                + "Accepting it because " + IdJagConstants.CONFIG_ALLOW_ACCESS_TOKEN_SUBJECT_TOKEN
                + " is enabled; this is outside the ID-JAG draft and the client should present an ID token.");
        return true;
    }

    private void validateTokenTimestamps(JWTClaimsSet claimsSet) throws IdentityOAuth2Exception {

        long currentTimeInMillis = System.currentTimeMillis();
        long timeStampSkewMillis = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000L;

        TokenExchangeUtils.checkExpirationTime(claimsSet.getExpirationTime(), currentTimeInMillis,
                timeStampSkewMillis);
        if (claimsSet.getNotBeforeTime() != null) {
            TokenExchangeUtils.checkNotBeforeTime(claimsSet.getNotBeforeTime(), currentTimeInMillis,
                    timeStampSkewMillis);
        }
        if (claimsSet.getIssueTime() != null) {
            TokenExchangeUtils.validateIssuedAtTime(claimsSet.getIssueTime(), currentTimeInMillis,
                    timeStampSkewMillis, IdJagConfig.getIatValidityPeriodInMinutes());
        }
    }

    /**
     * The client must present an identity assertion that was issued to itself, so the subject token's audience has to
     * name the requesting client. Assertions minted by a federated identity provider name that provider's configured
     * alias instead.
     */
    private void validateSubjectTokenAudience(JWTClaimsSet claimsSet, IdentityProvider identityProvider,
                                              String tenantDomain, String clientId) throws IdentityOAuth2Exception {

        List<String> audiences = claimsSet.getAudience();
        if (audiences == null || audiences.isEmpty()) {
            throw new IdentityOAuth2ClientException(OAuth2ErrorCodes.INVALID_REQUEST,
                    "The 'subject_token' must carry an 'aud' claim.");
        }
        if (audiences.contains(clientId)) {
            return;
        }
        String idpAlias = TokenExchangeUtils.getIDPAlias(identityProvider, tenantDomain);
        if (StringUtils.isNotBlank(idpAlias) && audiences.contains(idpAlias)) {
            return;
        }
        throw new IdentityOAuth2ClientException(IdJagConstants.INVALID_TARGET_ERROR_CODE,
                "The 'subject_token' was not issued to the requesting client. Its 'aud' claim must contain the "
                        + "client_id of the client presenting it.");
    }

    /**
     * Binds the resource owner asserted by the subject token to the message context.
     */
    private void setAuthorizedUser(OAuthTokenReqMessageContext tokReqMsgCtx, IdentityProvider identityProvider,
                                   String subject, JWTClaimsSet claimsSet, String tenantDomain, String clientId)
            throws IdentityOAuth2Exception {

        if (IdJagConstants.LOCAL_IDP_NAME.equals(identityProvider.getIdentityProviderName())) {
            // The assertion was minted by this server, so "sub" identifies a local user. Resolving it here (rather
            // than treating the user as federated) is what lets the email claim be read back from the user store.
            tokReqMsgCtx.setAuthorizedUser(resolveLocalUser(subject, tenantDomain, clientId));
        } else {
            // A federated assertion; reuse the stock linking logic, which honours the application's account
            // association configuration.
            TokenExchangeUtils.setAuthorizedUser(tokReqMsgCtx, identityProvider, subject, claimsSet);
        }
    }

    /**
     * Resolves a local user from the subject identifier of an assertion this server issued. The application's own
     * subject claim configuration is honoured first, so subjects that are usernames or custom claims resolve as well
     * as the default user id. A direct user id lookup is the fallback for applications with no subject claim set.
     */
    private AuthenticatedUser resolveLocalUser(String subject, String tenantDomain, String clientId)
            throws IdentityOAuth2Exception {

        try {
            return OAuth2Util.getAuthenticatedUserFromSubjectIdentifier(subject, tenantDomain, clientId);
        } catch (IdentityOAuth2Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Could not resolve the subject_token subject '" + subject + "' through the application's "
                        + "subject claim configuration. Retrying as a user id.", e);
            }
        }
        try {
            return OAuth2Util.getAuthenticatedUser(subject, tenantDomain, clientId);
        } catch (IdentityOAuth2Exception e) {
            throw new IdentityOAuth2ClientException(OAuth2ErrorCodes.INVALID_GRANT,
                    "No local user could be resolved for the subject asserted by the subject_token.", e);
        }
    }

    @Override
    public OAuth2AccessTokenRespDTO issue(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        if (!isIdJagRequest(tokReqMsgCtx)) {
            return super.issue(tokReqMsgCtx);
        }
        return IdJagTokenBuilder.issueIdJag(tokReqMsgCtx);
    }

    static boolean isIdJagRequest(OAuthTokenReqMessageContext tokReqMsgCtx) {

        return Boolean.TRUE.equals(tokReqMsgCtx.getProperty(IdJagConstants.PROP_ID_JAG_REQUEST));
    }

    /**
     * Flattens the token request parameters, keeping the first value of any repeated parameter.
     */
    private static Map<String, String> toRequestParamMap(OAuthTokenReqMessageContext tokReqMsgCtx) {

        RequestParameter[] parameters = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters();
        Map<String, String> requestParams = new HashMap<>();
        if (parameters == null) {
            return requestParams;
        }
        for (RequestParameter parameter : parameters) {
            String[] values = parameter.getValue();
            if (parameter.getKey() != null && values != null && values.length > 0) {
                requestParams.putIfAbsent(parameter.getKey(), values[0]);
            }
        }
        return requestParams;
    }


    private static String[] withoutOpenIdScope(String[] scopes) {

        if (scopes == null) {
            return new String[0];
        }
        return java.util.Arrays.stream(scopes)
                .filter(scope -> StringUtils.isNotBlank(scope) && !IdJagConstants.OPENID_SCOPE.equals(scope))
                .toArray(String[]::new);
    }

    static String resolveTenantDomain(OAuth2AccessTokenReqDTO tokenReqDTO) {

        String tenantDomain = tokenReqDTO.getTenantDomain();
        return StringUtils.isNotBlank(tenantDomain) ? tenantDomain : MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
    }
}
