package wdawson.samples.revoker.representations;

import java.math.BigInteger;
import javax.security.auth.x500.X500Principal;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static wdawson.samples.revoker.representations.CertificateSummary.DATE_TIME_FORMATTER;

/**
 * @author wdawson
 */
public class CertificateSummaryTest {
    private static final String VALID_LINE = "V\t161224002251Z\t\t100B\tunknown\t" +
            "/C=US/ST=California/L=San Francisco/O=test/OU=test/CN=test";
    private static final String VALID_EXPIRED_LINE = "V\t151215010838Z\t\t100B\tunknown\t" +
            "/C=US/ST=California/L=San Francisco/O=test/OU=test/CN=test";
    private static final String EXPIRED_LINE = "E\t151215010838Z\t\t100B\tunknown\t" +
            "/C=US/ST=California/L=San Francisco/O=test/OU=test/CN=test";
    private static final String REVOKED_EXPIRED_LINE = "R\t151215010838Z\t151215010837Z,certificateHold\t100B\tunknown\t" +
            "/C=US/ST=California/L=San Francisco/O=test/OU=test/CN=test";
    private static final String REVOKED_LINE = "R\t161224002251Z\t151215010837Z\t100B\tunknown\t" +
            "/C=US/ST=California/L=San Francisco/O=test/OU=test/CN=test";
    private static final String REVOKED_REASON_LINE = "R\t161224002251Z\t151215010837Z,certificateHold\t100B\tunknown\t" +
            "/C=US/ST=California/L=San Francisco/O=test/OU=test/CN=test";

    @Test
    public void testThatValidLineParsedCorrectly() {
        CertificateSummary revokedSummary = CertificateSummary.parseLine(VALID_LINE);
        CertificateSummary expected = CertificateSummary.newBuilder()
                .withStatus(CertificateStatus.VALID)
                .withExpirationTime(DATE_TIME_FORMATTER.parseDateTime("161224002251Z"))
                .withRevocationTime(null)
                .withRevocationReason(null)
                .withSerialNumber(new BigInteger("100B", 16))
                .withFileName(null)
                .withSubjectDN(new X500Principal("C=US, ST=California, L=San Francisco, O=test, OU=test, CN=test"))
                .build();

        assertThat(revokedSummary).isEqualToIgnoringGivenFields(expected, "thisUpdateTime");
    }

    @Test
    public void testThatDetectingExpiredLineParsedCorrectly() {
        CertificateSummary revokedSummary = CertificateSummary.parseLine(VALID_EXPIRED_LINE);
        CertificateSummary expected = CertificateSummary.newBuilder()
                .withStatus(CertificateStatus.EXPIRED)
                .withExpirationTime(DATE_TIME_FORMATTER.parseDateTime("151215010838Z"))
                .withSerialNumber(new BigInteger("100B", 16))
                .withFileName(null)
                .withSubjectDN(new X500Principal("C=US, ST=California, L=San Francisco, O=test, OU=test, CN=test"))
                .build();

        assertThat(revokedSummary).isEqualToIgnoringGivenFields(expected, "thisUpdateTime");
    }

    @Test
    public void testThatExpiredLineParsedCorrectly() {
        CertificateSummary revokedSummary = CertificateSummary.parseLine(EXPIRED_LINE);
        CertificateSummary expected = CertificateSummary.newBuilder()
                .withStatus(CertificateStatus.EXPIRED)
                .withExpirationTime(DATE_TIME_FORMATTER.parseDateTime("151215010838Z"))
                .withRevocationTime(null)
                .withRevocationReason(null)
                .withSerialNumber(new BigInteger("100B", 16))
                .withFileName(null)
                .withSubjectDN(new X500Principal("C=US, ST=California, L=San Francisco, O=test, OU=test, CN=test"))
                .build();

        assertThat(revokedSummary).isEqualToIgnoringGivenFields(expected, "thisUpdateTime");
    }

    @Test
    public void testThatExpiredAndRevokedParsedCorrectly() {
        CertificateSummary revokedSummary = CertificateSummary.parseLine(REVOKED_EXPIRED_LINE);
        CertificateSummary expected = CertificateSummary.newBuilder()
                .withStatus(CertificateStatus.REVOKED)
                .withExpirationTime(DATE_TIME_FORMATTER.parseDateTime("151215010838Z"))
                .withRevocationTime(DATE_TIME_FORMATTER.parseDateTime("151215010837Z"))
                .withRevocationReason(RevocationReason.CERTIFICATE_HOLD)
                .withSerialNumber(new BigInteger("100B", 16))
                .withFileName(null)
                .withSubjectDN(new X500Principal("C=US, ST=California, L=San Francisco, O=test, OU=test, CN=test"))
                .build();

        assertThat(revokedSummary).isEqualToIgnoringGivenFields(expected, "thisUpdateTime");
    }

    @Test
    public void testThatRevokedLineParsedCorrectly() {
        CertificateSummary revokedSummary = CertificateSummary.parseLine(REVOKED_LINE);
        CertificateSummary expected = CertificateSummary.newBuilder()
                .withStatus(CertificateStatus.REVOKED)
                .withExpirationTime(DATE_TIME_FORMATTER.parseDateTime("161224002251Z"))
                .withRevocationTime(DATE_TIME_FORMATTER.parseDateTime("151215010837Z"))
                .withRevocationReason(null)
                .withSerialNumber(new BigInteger("100B", 16))
                .withFileName(null)
                .withSubjectDN(new X500Principal("C=US, ST=California, L=San Francisco, O=test, OU=test, CN=test"))
                .build();

        assertThat(revokedSummary).isEqualToIgnoringGivenFields(expected, "thisUpdateTime");
    }

    @Test
    public void testThatRevokedLineWithReasonParsedCorrectly() {
        CertificateSummary revokedSummary = CertificateSummary.parseLine(REVOKED_REASON_LINE);
        CertificateSummary expected = CertificateSummary.newBuilder()
                .withStatus(CertificateStatus.REVOKED)
                .withExpirationTime(DATE_TIME_FORMATTER.parseDateTime("161224002251Z"))
                .withRevocationTime(DATE_TIME_FORMATTER.parseDateTime("151215010837Z"))
                .withRevocationReason(RevocationReason.CERTIFICATE_HOLD)
                .withSerialNumber(new BigInteger("100B", 16))
                .withFileName(null)
                .withSubjectDN(new X500Principal("C=US, ST=California, L=San Francisco, O=test, OU=test, CN=test"))
                .build();

        assertThat(revokedSummary).isEqualToIgnoringGivenFields(expected, "thisUpdateTime");
    }
}
