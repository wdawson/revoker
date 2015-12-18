package wdawson.samples.revoker.configuration;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Collections;
import java.util.List;
import javax.validation.Valid;
import javax.validation.constraints.Min;
import org.hibernate.validator.constraints.NotEmpty;
import wdawson.samples.revoker.representations.CRLNameFilePair;

/**
 * @author wdawson
 */
public class CertificateAuthorityConfiguration {

    /**
     * The file containing the CA's index.
     */
    @NotEmpty
    @JsonProperty
    private String caIndexFile;

    /**
     * How long to refresh the certificate status from the CA's index file in seconds.
     * Defaults to 300 (5 minutes).
     */
    @Min(0)
    @JsonProperty
    private int refreshSeconds = 300;

    @Valid
    @NotEmpty
    @JsonProperty
    private List<CRLNameFilePair> crlFiles = Collections.emptyList();

    public String getCaIndexFile() {
        return caIndexFile;
    }

    public void setCaIndexFile(String caIndexFile) {
        this.caIndexFile = caIndexFile;
    }

    public int getRefreshSeconds() {
        return refreshSeconds;
    }

    public void setRefreshSeconds(int refreshSeconds) {
        this.refreshSeconds = refreshSeconds;
    }

    public List<CRLNameFilePair> getCrlFiles() {
        return crlFiles;
    }

    public void setCrlFiles(List<CRLNameFilePair> crlFiles) {
        this.crlFiles = crlFiles;
    }
}
