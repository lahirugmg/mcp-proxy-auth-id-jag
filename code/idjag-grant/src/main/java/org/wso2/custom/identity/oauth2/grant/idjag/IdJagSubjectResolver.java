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

import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.Map;

/**
 * Resolves the value that becomes the ID-JAG {@code sub} claim.
 * <p>
 * The specification defines {@code sub} as "the subject identifier of the resource owner at the Resource
 * Application" — that is, the identifier the <em>other</em> authorization server knows the user by, not the one this
 * server uses internally. WSO2 Identity Server would otherwise put its own subject identifier (a UUID by default) in
 * that position, which the third party cannot resolve to an account. This resolver therefore reads the user's email
 * address instead, which is the identifier both sides share.
 * <p>
 * Resolution order:
 * <ol>
 *   <li>the claim as already carried on the authenticated user (populated for federated users);</li>
 *   <li>the claim read from the user store (the local user case);</li>
 *   <li>the corresponding claim in the subject token itself.</li>
 * </ol>
 * If none of these yields a value the request fails, unless
 * {@code OAuth.IDJAG.RequireSubjectClaim} is turned off.
 */
final class IdJagSubjectResolver {

    private static final Log log = LogFactory.getLog(IdJagSubjectResolver.class);

    private IdJagSubjectResolver() {

    }

    static String resolveSubject(AuthenticatedUser authenticatedUser, JWTClaimsSet subjectTokenClaims,
                                 String tenantDomain) throws IdentityOAuth2Exception {

        if (authenticatedUser == null) {
            throw new IdentityOAuth2Exception(OAuth2ErrorCodes.SERVER_ERROR,
                    "No authenticated user is bound to the ID-JAG request.");
        }
        String subjectClaimUri = IdJagConfig.getSubjectClaimUri();

        String subject = resolveClaim(authenticatedUser, subjectTokenClaims, tenantDomain, subjectClaimUri);
        if (StringUtils.isNotBlank(subject)) {
            return subject.trim();
        }

        String fallback = authenticatedUser.getAuthenticatedSubjectIdentifier();
        if (IdJagConfig.isSubjectClaimRequired()) {
            // Failing closed is deliberate: an ID-JAG carrying this server's UUID in "sub" would be accepted by the
            // resource application and mapped to the wrong account, or to no account at all.
            throw new IdentityOAuth2Exception(OAuth2ErrorCodes.SERVER_ERROR,
                    "Unable to resolve the claim '" + subjectClaimUri + "' for the user asserted by the "
                            + "subject_token, so no ID-JAG 'sub' can be issued. Ensure the user has a value for that "
                            + "claim, or set OAuth.IDJAG.RequireSubjectClaim to false to fall back to the subject "
                            + "identifier.");
        }
        log.warn("Could not resolve the claim '" + subjectClaimUri + "' for the user asserted by the subject_token. "
                + "Falling back to the subject identifier for the ID-JAG 'sub' claim because "
                + IdJagConstants.CONFIG_REQUIRE_SUBJECT_CLAIM + " is disabled.");
        return fallback;
    }

    /**
     * Reads one local claim for the user behind the request, trying each source in turn: the claims already on the
     * authenticated user (populated for federated users), then the local user store, then the subject token itself.
     *
     * @return the claim value, or null when no source has one.
     */
    static String resolveClaim(AuthenticatedUser authenticatedUser, JWTClaimsSet subjectTokenClaims,
                               String tenantDomain, String claimUri) throws IdentityOAuth2Exception {

        if (authenticatedUser == null || StringUtils.isBlank(claimUri)) {
            return null;
        }
        String value = resolveFromUserAttributes(authenticatedUser, claimUri);
        if (StringUtils.isBlank(value)) {
            value = resolveFromUserStore(authenticatedUser, claimUri, tenantDomain);
        }
        if (StringUtils.isBlank(value)) {
            value = resolveFromSubjectToken(subjectTokenClaims, claimUri);
        }
        return StringUtils.isBlank(value) ? null : value.trim();
    }

    /**
     * Federated users carry their claims on the authenticated user rather than in a local user store.
     */
    private static String resolveFromUserAttributes(AuthenticatedUser authenticatedUser, String subjectClaimUri) {

        Map<ClaimMapping, String> userAttributes = authenticatedUser.getUserAttributes();
        if (userAttributes == null || userAttributes.isEmpty()) {
            return null;
        }
        for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
            ClaimMapping claimMapping = entry.getKey();
            if (claimMapping == null || StringUtils.isBlank(entry.getValue())) {
                continue;
            }
            if (matches(claimMapping.getLocalClaim() == null ? null : claimMapping.getLocalClaim().getClaimUri(),
                    subjectClaimUri)
                    || matches(claimMapping.getRemoteClaim() == null ? null
                            : claimMapping.getRemoteClaim().getClaimUri(), subjectClaimUri)) {
                return entry.getValue();
            }
        }
        return null;
    }

    private static boolean matches(String claimUri, String subjectClaimUri) {

        return StringUtils.isNotBlank(claimUri) && claimUri.equals(subjectClaimUri);
    }

    /**
     * Reads the claim for a local user, by user id where one is known and by qualified username otherwise.
     */
    private static String resolveFromUserStore(AuthenticatedUser authenticatedUser, String subjectClaimUri,
                                               String tenantDomain) throws IdentityOAuth2Exception {

        if (authenticatedUser.isFederatedUser()) {
            return null;
        }
        try {
            UserRealm realm = IdentityTenantUtil.getRealm(tenantDomain, null);
            if (realm == null) {
                return null;
            }
            AbstractUserStoreManager userStoreManager =
                    (AbstractUserStoreManager) realm.getUserStoreManager();
            if (userStoreManager == null) {
                return null;
            }

            String userId = getUserId(authenticatedUser);
            if (StringUtils.isNotBlank(userId)) {
                String value = userStoreManager.getUserClaimValueWithID(userId, subjectClaimUri, null);
                if (StringUtils.isNotBlank(value)) {
                    return value;
                }
            }

            String qualifiedUsername = getQualifiedUsername(authenticatedUser);
            if (StringUtils.isNotBlank(qualifiedUsername)) {
                return userStoreManager.getUserClaimValue(qualifiedUsername, subjectClaimUri, null);
            }
            return null;
        } catch (UserStoreException | IdentityException e) {
            throw new IdentityOAuth2Exception(OAuth2ErrorCodes.SERVER_ERROR,
                    "Error while reading the claim '" + subjectClaimUri + "' from the user store of tenant: "
                            + tenantDomain, e);
        }
    }

    private static String getUserId(AuthenticatedUser authenticatedUser) {

        try {
            return authenticatedUser.getUserId();
        } catch (UserIdNotFoundException e) {
            if (log.isDebugEnabled()) {
                log.debug("No user id is available on the authenticated user; falling back to a username based "
                        + "claim lookup.", e);
            }
            return null;
        }
    }

    /**
     * Builds the user store qualified, tenant-free username the user store manager expects.
     */
    private static String getQualifiedUsername(AuthenticatedUser authenticatedUser) {

        String username = authenticatedUser.getUserName();
        if (StringUtils.isBlank(username)) {
            String fullyQualified = authenticatedUser.toFullQualifiedUsername();
            return StringUtils.isBlank(fullyQualified) ? null
                    : MultitenantUtils.getTenantAwareUsername(fullyQualified);
        }
        String userStoreDomain = authenticatedUser.getUserStoreDomain();
        return StringUtils.isBlank(userStoreDomain) ? username : userStoreDomain + "/" + username;
    }

    /**
     * Last resort: the subject token may already carry the claim, keyed either by its OIDC name or by the configured
     * local claim URI.
     */
    private static String resolveFromSubjectToken(JWTClaimsSet subjectTokenClaims, String subjectClaimUri) {

        if (subjectTokenClaims == null) {
            return null;
        }
        Object value = subjectTokenClaims.getClaim(subjectClaimUri);
        if (value == null && IdJagConstants.DEFAULT_SUBJECT_CLAIM_URI.equals(subjectClaimUri)) {
            value = subjectTokenClaims.getClaim(IdJagConstants.EMAIL_CLAIM);
        }
        return value == null ? null : String.valueOf(value);
    }
}
