package wdawson.samples.revoker.configuration;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.dropwizard.Configuration;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

/**
 * Configuration for the Revoker application
 *
 * @author wdawson
 */
public class RevokerConfiguration extends Configuration {

    @Valid
    @NotNull
    @JsonProperty
    private OCSPResponderConfiguration ocspResponder;

    @Valid
    @NotNull
    @JsonProperty
    private CertificateAuthorityConfiguration certificateAuthority;

    public OCSPResponderConfiguration getOcspResponder() {
        return ocspResponder;
    }

    public void setOcspResponder(OCSPResponderConfiguration ocspResponder) {
        this.ocspResponder = ocspResponder;
    }

    public CertificateAuthorityConfiguration getCertificateAuthority() {
        return certificateAuthority;
    }

    public void setCertificateAuthority(CertificateAuthorityConfiguration certificateAuthority) {
        this.certificateAuthority = certificateAuthority;
    }
}
