package wdawson.samples.revoker.health;

import com.codahale.metrics.health.HealthCheck;
import com.google.common.util.concurrent.Service;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import wdawson.samples.revoker.managers.CertificateManager;

/**
 * HealthCheck for the OCSP functionality
 *
 * @author wdawson
 */
public class OCSPHealthCheck extends HealthCheck {
    private static final Logger LOG = LoggerFactory.getLogger(OCSPHealthCheck.class);

    private X509Certificate[] signingCertificateChain;

    private CertificateManager certificateManager;

    public OCSPHealthCheck(CertificateManager certificateManager, X509Certificate[] signingCertificateChain) {
        this.certificateManager = certificateManager;
        this.signingCertificateChain = signingCertificateChain;
    }

    @Override
    protected Result check() throws Exception {
        if (!isValidSigningCertificateChain(signingCertificateChain)) {
            return Result.unhealthy("Signing certificate chain is invalid.");
        }
        if (!isCertificateManagerHealthy()) {
            return Result.unhealthy("CertificateManager is not healthy.");
        }

        return Result.healthy();
    }

    private boolean isValidSigningCertificateChain(X509Certificate[] signingCertificateChain) {
        // Verify issuing chain
        if (signingCertificateChain.length > 1) {
            X500Principal expectedPrincipal = signingCertificateChain[0].getIssuerX500Principal();
            for (int i = 1; i < signingCertificateChain.length; ++i) { // start at the direct issuer
                X500Principal subject = signingCertificateChain[i].getSubjectX500Principal();
                if (!subject.equals(expectedPrincipal)) {
                    LOG.error("Expecting: " + expectedPrincipal + " But found: " + subject);
                    return false;
                }
                expectedPrincipal = signingCertificateChain[i].getIssuerX500Principal();
            }
        }

        // Check validity of the signing certificate;
        try {
            signingCertificateChain[0].checkValidity();
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            LOG.error("Signing certificate was invalid!");
            return false;
        }

        // All good
        return true;
    }

    private boolean isCertificateManagerHealthy() {
        Service.State dataUpdaterState = certificateManager.isDataUpdaterRunning();
        if (dataUpdaterState == Service.State.RUNNING) {
            return true;
        } else {
            LOG.error("DataUpdater not running. It is " + dataUpdaterState.name());
            return false;
        }
    }
}
