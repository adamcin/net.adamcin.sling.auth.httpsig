/*
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * For more information, please refer to <http://unlicense.org/>
 */

package net.adamcin.sling.auth.httpsig.impl;

import net.adamcin.httpsig.api.Authorization;
import net.adamcin.httpsig.api.Challenge;
import net.adamcin.httpsig.api.Constants;
import net.adamcin.httpsig.api.DefaultKeychain;
import net.adamcin.httpsig.api.Keychain;
import net.adamcin.httpsig.api.RequestContent;
import net.adamcin.httpsig.api.Verifier;
import net.adamcin.httpsig.api.VerifyResult;
import net.adamcin.httpsig.http.servlet.ServletUtil;
import net.adamcin.httpsig.ssh.jce.AuthorizedKeys;
import net.adamcin.httpsig.ssh.jce.UserFingerprintKeyId;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.Service;
import org.apache.jackrabbit.api.security.authentication.token.TokenCredentials;
import org.apache.sling.auth.core.spi.AuthenticationHandler;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.commons.osgi.OsgiUtil;
import org.apache.sling.jcr.api.SlingRepository;
import org.apache.sling.settings.SlingSettingsService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.Credentials;
import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.SimpleCredentials;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * Implementation of {@link AuthenticationHandler} to support HTTP Signature authentication for one configured user,
 * such as the admin user or another user designated for use by automated deployment and configuration management
 * systems. This relies on JCR Token authentication to establish trusted repository login.
 *
 * TODO: support more than one user
 */
@Component(label = "%httpsig.name", description = "%httpsig.description", metatype = true)
@Service
@Properties({
    @Property(name = org.apache.sling.auth.core.spi.AuthenticationHandler.PATH_PROPERTY, value = "/",
              label = "%httpsig.path.name", description = "%httpsig.path.description"),
    @Property(name = "service.ranking", intValue = 2500, label = "%httpsig.ranking.name",
              description = "%httpsig.ranking.description") })
public class SignatureAuthenticationHandler
        implements AuthenticationHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(SignatureAuthenticationHandler.class);

    @Property(value = "date")
    private static final String OSGI_HEADERS = "httpsig.headers";

    @Property(value = "Sling (Development)")
    private static final String OSGI_REALM = "httpsig.realm";

    @Property(longValue = 300000L)
    private static final String OSGI_SKEW = "httpsig.skew";

    @Property(value = "admin")
    private static final String OSGI_USERNAME = "httpsig.username";

    @Property
    private static final String OSGI_AUTHORIZED_KEYS = "httpsig.authkeys";

    @Reference
    private SlingRepository repository;

    @Reference
    private SlingSettingsService slingSettingsService;

    private String realm;
    private List<String> headers;
    private long skew;
    private Keychain keychain;
    private Challenge challenge;
    private String username;
    private Credentials userCredentials;
    private UserFingerprintKeyId keyIdentifier;
    private String authorizedKeys;

    @Activate
    protected void activate(Map<String, Object> props) {
        this.realm = OsgiUtil.toString(props.get(OSGI_REALM), "");
        String headersString = OsgiUtil.toString(props.get(OSGI_HEADERS), "");
        this.headers = headersString.trim().isEmpty() ? Constants.DEFAULT_HEADERS : Constants.parseTokens(headersString);
        this.skew = OsgiUtil.toLong(props.get(OSGI_SKEW), 1L);
        this.username = OsgiUtil.toString(props.get(OSGI_USERNAME), "");
        this.authorizedKeys = OsgiUtil.toString(props.get(OSGI_AUTHORIZED_KEYS), null);
        this.keyIdentifier = new UserFingerprintKeyId(this.username);
        this.keychain = this.loadKeychain();
        this.challenge = new Challenge(this.realm, this.headers, this.keychain.getAlgorithms());
    }

    @Deactivate
    protected void deactivate(Map<String, Object> props) {
        this.realm = null;
        this.headers = null;
        this.skew = -1L;
        this.username = null;
        this.authorizedKeys = null;
        this.keyIdentifier = null;
        this.keychain = null;
        this.challenge = null;
        this.userCredentials = null;
    }

    private Keychain loadKeychain() {
        try {
            if (this.authorizedKeys == null || this.authorizedKeys.trim().isEmpty()) {
                File slingHomeAuthKeys = new File(slingSettingsService.getSlingHomePath(), "../.ssh/authorized_keys");
                if (slingHomeAuthKeys.exists()) {
                    return AuthorizedKeys.newKeychain(slingHomeAuthKeys);
                } else {
                    return AuthorizedKeys.defaultKeychain();
                }
            } else {
                return AuthorizedKeys.newKeychain(new File(this.authorizedKeys));
            }
        } catch (IOException e) {
            LOGGER.error("[loadKeychain] failed to get a keychain.", e);
        }
        return new DefaultKeychain();
    }

    public AuthenticationInfo extractCredentials(HttpServletRequest request, HttpServletResponse response) {
        Authorization authz = ServletUtil.getAuthorization(request);
        if (authz != null) {
            RequestContent requestContent = ServletUtil.getRequestContent(request);

            AuthenticationInfo info = extractCredentials(authz, requestContent);
            if (info != null) {
                return info;
            } else {
                try {
                    if (ServletUtil.sendChallenge(response, this.challenge)) {
                        return AuthenticationInfo.DOING_AUTH;
                    }
                } catch (IOException e) {
                    LOGGER.warn("[extractCredentials] failed to send challenge.");
                }
            }
        }

        return null;
    }

    private AuthenticationInfo extractCredentials(Authorization authz, RequestContent requestContent) {
        if (authz != null) {
            Verifier verifier = new Verifier(this.keychain, this.keyIdentifier);
            verifier.setSkew(this.skew);
            VerifyResult result = verifier.verifyWithResult(this.challenge, requestContent, authz);

            if (result == VerifyResult.SUCCESS) {
                this.userCredentials = getCredentials(this.username, this.userCredentials);
                return this.createAuthInfo(this.username, this.userCredentials);
            } else {
                if (LOGGER.isDebugEnabled()) {
                    switch (result) {
                        case CHALLENGE_NOT_SATISFIED:
                            LOGGER.debug("[extractCredentials] verify result: {}, cHeaders: {}, aHeaders: {}",
                                    new Object[]{result, challenge.getHeaders(), authz.getHeaders()}
                            );
                            break;
                        case EXPIRED_DATE_HEADER:
                            LOGGER.debug("[extractCredentials] verify result: {}, skewMS: {}, date header: {}",
                                         new Object[]{ result, verifier.getSkew(), requestContent.getDate() });
                            break;
                        case FAILED_KEY_VERIFY:
                        case INCOMPLETE_REQUEST:
                            LOGGER.debug("[extractCredentials] verify result: {}, aHeaders: {}, rHeaders: {}, request-line: {}",
                                         new Object[]{ result,
                                                 authz.getHeaders(),
                                                 requestContent.getHeaderNames(),
                                                 requestContent.getRequestLine() });
                            break;
                        case KEY_NOT_FOUND:
                            LOGGER.debug("[extractCredentials] verify result: {}, keyId: {}",
                                         new Object[]{ result, authz.getKeyId() });
                            break;
                        default:
                            LOGGER.error("[extractCredentials] verify result: {}", result);
                    }
                }
            }
        }

        return null;
    }

    private Credentials getCredentials(String userId, Credentials oldCredentials) {
        if (oldCredentials != null) {
            Session oldCredentialsSession = null;
            try {
                oldCredentialsSession = this.repository.login(oldCredentials);
                return oldCredentials;
            } catch (RepositoryException e) {
                LOGGER.info("[createCredentials] failed to login using old credentials. Creating new credentials.", e);
            } finally {
                if (oldCredentialsSession != null) {
                    oldCredentialsSession.logout();
                }
            }
        }

        Session userSession = null;
        Session adminSession = null;
        try {
            adminSession = this.repository.loginAdministrative(null);
            SimpleCredentials newCredentials = new SimpleCredentials(userId, new char[0]);
            newCredentials.setAttribute(".token", "");
            userSession = adminSession.impersonate(newCredentials);
            return new TokenCredentials((String) newCredentials.getAttribute(".token"));
        } catch (RepositoryException e) {
            LOGGER.error("[createCredentials] failed to create credentials for user: " + this.username, e);
        } finally {
            if (userSession != null) {
                userSession.logout();
            }
            if (adminSession != null) {
                adminSession.logout();
            }
        }
        return null;
    }

    private AuthenticationInfo createAuthInfo(String userId, Credentials credentials) {
        if (credentials != null) {
            AuthenticationInfo info = new AuthenticationInfo(Constants.SCHEME, userId);
            info.put("user.jcr.credentials", credentials);
            return info;
        }
        return null;
    }

    public boolean requestCredentials(HttpServletRequest request, HttpServletResponse response) throws IOException {
        return false;
    }

    public void dropCredentials(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // do nothing
    }
}
