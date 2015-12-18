package wdawson.samples.revoker.managers;

import com.google.common.collect.Lists;
import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import javax.security.auth.x500.X500Principal;
import org.junit.Before;
import org.junit.Test;
import wdawson.samples.revoker.representations.CRLNameFilePair;
import wdawson.samples.revoker.representations.CertificateStatus;
import wdawson.samples.revoker.representations.CertificateSummary;

import static io.dropwizard.testing.ResourceHelpers.resourceFilePath;
import static org.assertj.core.api.Assertions.assertThat;
import static wdawson.samples.revoker.representations.CertificateSummary.DATE_TIME_FORMATTER;

/**
 * @author wdawson
 */
public class CertificateManagerTest {

    private CertificateManager certificateManager;

    private static final String CRL_NAME = "crl.pem";

    @Before
    public void setup() {
        certificateManager = new CertificateManager(resourceFilePath("index.txt"),
                Lists.newArrayList(new CRLNameFilePair(CRL_NAME, resourceFilePath("crl/crl.pem"))),
                10);
    }

    @Test
    public void crlFileCanBeParsed() throws Exception {
        certificateManager.newNonRunningDataUpdater().refreshCRLs();

        X509CRL crl = certificateManager.getCRL(CRL_NAME);
        assertThat(crl).isNotNull();
        assertThat(crl.getRevokedCertificates()).hasSize(1);
        X509CRLEntry crlEntry = crl.getRevokedCertificate(new BigInteger("1002", 16));
        assertThat(crlEntry).isNotNull();
        assertThat(crlEntry.getRevocationDate()).isEqualTo(DATE_TIME_FORMATTER.parseDateTime("151217225905Z").toDate());
    }

    @Test
    public void indexFileCanBeParsed() throws Exception {
        certificateManager.newNonRunningDataUpdater().parseIndexFile();

        CertificateSummary summary = certificateManager.getSummary(new BigInteger("1002", 16));

        CertificateSummary expected = CertificateSummary.newBuilder()
                .withStatus(CertificateStatus.REVOKED)
                .withExpirationTime(DATE_TIME_FORMATTER.parseDateTime("161226225851Z"))
                .withRevocationTime(DATE_TIME_FORMATTER.parseDateTime("151217225905Z"))
                .withRevocationReason(null)
                .withSerialNumber(new BigInteger("1002", 16))
                .withFileName(null)
                .withSubjectDN(new X500Principal("C=US, ST=California, L=San Francisco, O=test, OU=test, CN=two"))
                .build();
        assertThat(summary).isEqualToIgnoringGivenFields(expected, "thisUpdateTime");
    }
}
