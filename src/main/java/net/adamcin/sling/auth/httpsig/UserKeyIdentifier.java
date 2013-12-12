package net.adamcin.sling.auth.httpsig;

import net.adamcin.httpsig.api.Key;
import net.adamcin.httpsig.api.KeyIdentifier;
import net.adamcin.httpsig.jce.FingerprintableKey;

/**
 * Implementation of {@link KeyIdentifier} which incorporates a username into the keyId string.
 */
public class UserKeyIdentifier implements KeyIdentifier {
    private String username;

    public UserKeyIdentifier(String username) {
        this.username = username;
    }

    public String getId(Key key) {
        if (key instanceof FingerprintableKey) {
            return String.format("/%s/%s", username, ((FingerprintableKey) key).getFingerprint());
        }
        return null;
    }

    public String getUsername() {
        return this.username;
    }

}
