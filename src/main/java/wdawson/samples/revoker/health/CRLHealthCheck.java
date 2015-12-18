package wdawson.samples.revoker.health;

import com.codahale.metrics.health.HealthCheck;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import wdawson.samples.revoker.representations.CRLNameFilePair;

/**
 * Handles health checks for the CRL Distribution Point
 *
 * @author wdawson
 */
public class CRLHealthCheck extends HealthCheck {
    private static final Logger LOG = LoggerFactory.getLogger(CRLHealthCheck.class);

    private List<CRLNameFilePair> crlFiles;

    private final CertificateFactory certificateFactory;

    public CRLHealthCheck(List<CRLNameFilePair> crlFiles) throws Exception {
        this.crlFiles = crlFiles;
        this.certificateFactory = CertificateFactory.getInstance("X.509");
    }

    @Override
    protected Result check() throws Exception {
        try {
            checkThatAllCRLFilesAreReadable();
            return Result.healthy();
        } catch (Exception e) {
            return Result.unhealthy(e);
        }
    }

    private void checkThatAllCRLFilesAreReadable() {
        crlFiles.forEach(pair -> makeCRL(pair.getFilePath()));
    }

    private X509CRL makeCRL(String fileName) {
        try (InputStream crlStream = new FileInputStream(fileName)) {
            return (X509CRL) certificateFactory.generateCRL(crlStream);
        } catch (Exception e) {
            throw new IllegalStateException("Could not parse CRL: " + fileName, e);
        }
    }
}
