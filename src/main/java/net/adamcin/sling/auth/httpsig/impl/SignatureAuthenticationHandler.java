package net.adamcin.sling.auth.httpsig.impl;

import net.adamcin.httpsig.api.Authorization;
import net.adamcin.httpsig.api.Challenge;
import net.adamcin.httpsig.api.Constants;
import net.adamcin.httpsig.api.DefaultKeychain;
import net.adamcin.httpsig.api.Keychain;
import net.adamcin.httpsig.api.SignatureBuilder;
import net.adamcin.httpsig.api.Verifier;
import net.adamcin.httpsig.helpers.servlet.ServletUtil;
import net.adamcin.httpsig.jce.AuthorizedKeys;
import net.adamcin.sling.auth.httpsig.UserKeyIdentifier;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.Service;
import org.apache.jackrabbit.api.security.authentication.token.TokenCredentials;
import org.apache.sling.auth.core.spi.AuthenticationHandler;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.commons.osgi.OsgiUtil;
import org.apache.sling.jcr.api.SlingRepository;
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
 *
 */
@Component(label = "%auth.httpsig.name", description = "%auth.httpsig.description")
@Service
@Properties({
    @Property(name = org.apache.sling.auth.core.spi.AuthenticationHandler.PATH_PROPERTY, value = "/"),
    @Property(name = "service.ranking", intValue = 2500, propertyPrivate = false) })
public class SignatureAuthenticationHandler
        implements AuthenticationHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(SignatureAuthenticationHandler.class);

    @Property(value = "request-line date")
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

    private String realm;
    private List<String> headers;
    private long skew;
    private Keychain keychain;
    private Challenge challenge;
    private String username;
    private Credentials userCredentials;
    private UserKeyIdentifier keyIdentifier;
    private String authorizedKeys;

    @Activate
    protected void activate(Map<String, Object> props) {
        this.realm = OsgiUtil.toString(props.get(OSGI_REALM), "");
        String headersString = OsgiUtil.toString(props.get(OSGI_HEADERS), "");
        this.headers = headersString.trim().isEmpty() ? Constants.DEFAULT_HEADERS : Constants.parseTokens(headersString);
        this.skew = OsgiUtil.toLong(props.get(OSGI_SKEW), 1L);
        this.username = OsgiUtil.toString(props.get(OSGI_USERNAME), "");
        this.authorizedKeys = OsgiUtil.toString(props.get(OSGI_AUTHORIZED_KEYS), null);
        this.keyIdentifier = new UserKeyIdentifier(this.username);
        this.keychain = this.loadKeychain();
        this.challenge = new Challenge(this.realm, this.headers, this.keychain.getAlgorithms());
    }

    private Keychain loadKeychain() {
        try {
            if (this.authorizedKeys == null) {
                return AuthorizedKeys.defaultKeychain();
            } else {
                return AuthorizedKeys.newKeychain(new File(this.authorizedKeys));
            }
        } catch (IOException e) {
            LOGGER.error("[getKeychain] failed to get a keychain.", e);
        }
        return new DefaultKeychain();
    }

    public AuthenticationInfo extractCredentials(HttpServletRequest request, HttpServletResponse response) {
        Authorization authz = ServletUtil.getAuthorization(request);
        if (authz != null) {
            SignatureBuilder signatureBuilder = ServletUtil.getSignatureBuilder(request);

            AuthenticationInfo info = extractCredentials(authz, signatureBuilder);
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

    private AuthenticationInfo extractCredentials(Authorization authz, SignatureBuilder signatureBuilder) {
        if (authz != null) {
            Verifier verifier = new Verifier(this.keychain, this.keyIdentifier);
            verifier.setSkew(this.skew);
            if (verifier.verify(this.challenge, signatureBuilder, authz)) {
                this.userCredentials = getCredentials(this.username, this.userCredentials);
                return this.createAuthInfo(this.username, this.userCredentials);
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
