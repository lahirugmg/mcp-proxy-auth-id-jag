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
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.security.Key;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

/**
 * Mints the signed {@code oauth-id-jag+jwt} returned by an ID-JAG token exchange.
 * <p>
 * The grant is not an access token: it is never persisted, has no refresh token, and is reported with
 * {@code token_type=N_A}. It is signed with the tenant's own key so that a resource application which already trusts
 * this server's OpenID Connect metadata can validate it with the keys it has.
 */
final class IdJagTokenBuilder {

    private static final Log log = LogFactory.getLog(IdJagTokenBuilder.class);

    private IdJagTokenBuilder() {

    }

    static OAuth2AccessTokenRespDTO issueIdJag(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        OAuth2AccessTokenReqDTO tokenReqDTO = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
        String tenantDomain = IdJagGrantHandler.resolveTenantDomain(tokenReqDTO);
        String requestingClientId = tokenReqDTO.getClientId();
        // The claim must name a client the resource application's authorization server knows, which is usually a
        // different registration from the one that authenticated here. See IdJagConfig.resolveClientIdClaim.
        String clientId = IdJagConfig.resolveClientIdClaim(requestingClientId);
        String audience = (String) tokReqMsgCtx.getProperty(IdJagConstants.PROP_ID_JAG_AUDIENCE);
        JWTClaimsSet subjectTokenClaims =
                (JWTClaimsSet) tokReqMsgCtx.getProperty(IdJagConstants.PROP_ID_JAG_SUBJECT_CLAIMS);
        AuthenticatedUser authenticatedUser = tokReqMsgCtx.getAuthorizedUser();

        String subject = IdJagSubjectResolver.resolveSubject(authenticatedUser, subjectTokenClaims, tenantDomain);
        long validityPeriodInSeconds = IdJagConfig.getValidityPeriodInSeconds();

        // Whatever survived the framework's scope validation: the scopes this user's roles and this application's
        // authorised API resources actually permit. "openid" is dropped from the claim because it is an
        // OpenID Connect request marker for this server, not an authority at the resource application.
        String scope = joinScopes(tokReqMsgCtx.getScope());

        long issuedAtInMillis = System.currentTimeMillis();
        long expiresAtInMillis = issuedAtInMillis + (validityPeriodInSeconds * 1000L);

        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .issuer(resolveIssuer(tenantDomain))
                .subject(subject)
                .audience(audience)
                .claim(IdJagConstants.CLIENT_ID_CLAIM, clientId)
                .issueTime(new Date(issuedAtInMillis))
                .expirationTime(new Date(expiresAtInMillis));
        if (StringUtils.isNotBlank(scope)) {
            claims.claim(IdJagConstants.SCOPE_CLAIM, scope);
        }
        String resourceClaim = resolveResourceClaim(tokReqMsgCtx);
        if (resourceClaim != null) {
            claims.claim(IdJagConstants.RESOURCE_CLAIM, resourceClaim);
        }

        addAdditionalClaims(claims, authenticatedUser, subjectTokenClaims, tenantDomain);
        for (Map.Entry<String, String> entry : IdJagConfig.getStaticClaims().entrySet()) {
            claims.claim(entry.getKey(), coerce(entry.getValue()));
        }

        String idJag = sign(claims.build(), tenantDomain);

        if (log.isDebugEnabled()) {
            log.debug("Issued an ID-JAG to client: " + requestingClientId + " with client_id claim: " + clientId
                    + " for audience: " + audience + (resourceClaim == null ? "" : " and resource: " + resourceClaim)
                    + " valid for " + validityPeriodInSeconds + " seconds.");
        }

        OAuth2AccessTokenRespDTO tokenRespDTO = new OAuth2AccessTokenRespDTO();
        // RFC 8693 carries the issued token in access_token regardless of its type.
        tokenRespDTO.setAccessToken(idJag);
        tokenRespDTO.setTokenType(IdJagConstants.TOKEN_TYPE_NOT_APPLICABLE);
        tokenRespDTO.setExpiresIn(validityPeriodInSeconds);
        tokenRespDTO.setExpiresInMillis(validityPeriodInSeconds * 1000L);
        tokenRespDTO.setAuthorizedScopes(scope);
        tokenRespDTO.addParameter(IdJagConstants.ISSUED_TOKEN_TYPE, IdJagConstants.ID_JAG_TOKEN_TYPE);
        return tokenRespDTO;
    }

    /**
     * The ID-JAG {@code resource} claim: which protected resource this grant buys access to. {@code aud} names the
     * authorization server that will redeem the grant, which is not the same thing -- one authorization server
     * fronts many resources, so without this claim it cannot always tell what is being asked for.
     * <p>
     * Prefers the configured value, then the request's optional {@code resource} parameter. Returns null when the
     * client sent none and nothing is configured, in which case the claim is omitted, as the draft allows.
     */
    private static String resolveResourceClaim(OAuthTokenReqMessageContext tokReqMsgCtx) {

        String configured = IdJagConfig.getResource();
        if (configured != null) {
            return configured;
        }
        return (String) tokReqMsgCtx.getProperty(IdJagConstants.PROP_ID_JAG_RESOURCE);
    }

    /**
     * Copies any claims named by {@code oauth.idjag.additional_claims} into the grant. A claim the user has no value
     * for is skipped rather than emitted empty, so a resource application never sees a blank assertion of fact.
     */
    private static void addAdditionalClaims(JWTClaimsSet.Builder claims, AuthenticatedUser authenticatedUser,
                                            JWTClaimsSet subjectTokenClaims, String tenantDomain)
            throws IdentityOAuth2Exception {

        for (Map.Entry<String, String> entry : IdJagConfig.getAdditionalClaims().entrySet()) {
            String name = entry.getKey();
            String value = IdJagSubjectResolver.resolveClaim(authenticatedUser, subjectTokenClaims, tenantDomain,
                    entry.getValue());
            if (value == null) {
                if (log.isDebugEnabled()) {
                    log.debug("No value for local claim '" + entry.getValue() + "'; omitting ID-JAG claim '" + name
                            + "'.");
                }
                continue;
            }
            claims.claim(name, coerce(value));
        }
    }

    /**
     * User store values arrive as strings. A claim such as {@code emailVerified} is semantically boolean, and a
     * consumer checking {@code claim === true} would be misled by the string "true", so booleans are emitted as
     * booleans. Anything else is passed through unchanged.
     */
    private static Object coerce(String value) {

        if ("true".equalsIgnoreCase(value)) {
            return Boolean.TRUE;
        }
        if ("false".equalsIgnoreCase(value)) {
            return Boolean.FALSE;
        }
        return value;
    }

    /**
     * The ID-JAG {@code iss}: the configured issuer if a deployment pinned one, otherwise this server's own OpenID
     * Connect token issuer, which is what a resource application validating against published metadata expects.
     */
    private static String resolveIssuer(String tenantDomain) throws IdentityOAuth2Exception {

        String configured = IdJagConfig.getIssuer();
        if (configured != null) {
            return configured;
        }
        return OAuth2Util.getIdTokenIssuer(tenantDomain);
    }

    /**
     * Signs the grant with the tenant key, stamping the mandatory {@code oauth-id-jag+jwt} JOSE type so a resource
     * application can tell an ID-JAG apart from an ID token signed by the same key.
     */
    private static String sign(JWTClaimsSet claims, String tenantDomain) throws IdentityOAuth2Exception {

        String signatureAlgorithm = OAuthServerConfiguration.getInstance().getIdTokenSignatureAlgorithm();
        JWSAlgorithm jwsAlgorithm = OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(signatureAlgorithm);

        int tenantId = OAuth2Util.getTenantId(tenantDomain);
        Key privateKey = OAuth2Util.getPrivateKey(tenantDomain, tenantId);
        if (!(privateKey instanceof RSAPrivateKey)) {
            throw new IdentityOAuth2Exception(OAuth2ErrorCodes.SERVER_ERROR,
                    "ID-JAG signing requires an RSA private key for tenant: " + tenantDomain + ", but the configured "
                            + "key is of type: " + privateKey.getClass().getName());
        }
        Certificate certificate = OAuth2Util.getCertificate(tenantDomain, tenantId);

        JWSHeader header = new JWSHeader.Builder(jwsAlgorithm)
                .type(new JOSEObjectType(IdJagConstants.ID_JAG_JWT_TYPE))
                .keyID(OAuth2Util.getKID(certificate, jwsAlgorithm, tenantDomain))
                .build();

        SignedJWT signedJWT = new SignedJWT(header, claims);
        try {
            signedJWT.sign(OAuth2Util.createJWSSigner((RSAPrivateKey) privateKey));
        } catch (JOSEException e) {
            throw new IdentityOAuth2Exception(OAuth2ErrorCodes.SERVER_ERROR, "Error while signing the ID-JAG.", e);
        }
        return signedJWT.serialize();
    }

    private static String joinScopes(String[] scopes) {

        if (scopes == null || scopes.length == 0) {
            return StringUtils.EMPTY;
        }
        StringBuilder joined = new StringBuilder();
        for (String scope : scopes) {
            if (StringUtils.isBlank(scope) || IdJagConstants.OPENID_SCOPE.equals(scope)) {
                continue;
            }
            if (joined.length() > 0) {
                joined.append(' ');
            }
            joined.append(scope);
        }
        return joined.toString();
    }
}
