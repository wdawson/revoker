package wdawson.samples.revoker.configuration;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.dropwizard.validation.OneOf;
import org.hibernate.validator.constraints.NotEmpty;

import javax.validation.constraints.NotNull;

/**
 * @author wdawson
 */
public class OCSPResponderConfiguration {

    /**
     * The absolute path of the KeyStore on the file system.
     */
    @NotEmpty
    @JsonProperty
    private String keyStorePath;

    /**
     * The type of KeyStore
     */
    @NotEmpty
    @OneOf({
            "JKS",          /** {@link sun.security.provider.Sun}      **/
            "JCEKS",        /** {@link sun.security.ssl.SunJSSE}       **/
            "PCKS12",       /** {@link com.sun.crypto.provider.SunJCE} **/
            "Windows-MY",   /** {@link sun.security.mscapi.SunMSCAPI}  **/
            "Windows-ROOT", /** {@link sun.security.mscapi.SunMSCAPI}  **/
            "KeychainStore" /** {@link apple.security.AppleProvider}   **/
    })
    @JsonProperty
    private String keyStoreType = "JKS";

    /**
     * The KeyStore passphrase.
     * Default: ""
     */
    @NotNull
    @JsonProperty
    private String keyStorePassphrase = "";

    /**
     * The alias within the KeyStore to find the signing keys
     */
    @NotEmpty
    @JsonProperty
    private String keyStoreAlias;

    /**
     * Whether to reject unknown certificates with "revoked" or return the "unknown" status.
     */
    @JsonProperty
    private boolean rejectUnknown = false;

    public String getKeyStorePath() {
        return keyStorePath;
    }

    public void setKeyStorePath(String keyStorePath) {
        this.keyStorePath = keyStorePath;
    }

    public String getKeyStoreType() {
        return keyStoreType;
    }

    public void setKeyStoreType(String keyStoreType) {
        this.keyStoreType = keyStoreType;
    }

    public String getKeyStorePassphrase() {
        return keyStorePassphrase;
    }

    public void setKeyStorePassphrase(String keyStorePassphrase) {
        this.keyStorePassphrase = keyStorePassphrase;
    }

    public String getKeyStoreAlias() {
        return keyStoreAlias;
    }

    public void setKeyStoreAlias(String keyStoreAlias) {
        this.keyStoreAlias = keyStoreAlias;
    }

    public boolean isRejectUnknown() {
        return rejectUnknown;
    }

    public void setRejectUnknown(boolean rejectUnknown) {
        this.rejectUnknown = rejectUnknown;
    }
}
