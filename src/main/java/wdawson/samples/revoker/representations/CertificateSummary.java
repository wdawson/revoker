package wdawson.samples.revoker.representations;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Splitter;
import java.math.BigInteger;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.apache.commons.lang3.StringUtils;
import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

/**
 * Represents the line in a CA's index file. The file is formatted with
 * the following fields separated by TAB characters.
 *
 * 1. Certificate status flag (V=valid, R=revoked, E=expired).
 * 2. Certificate expiration date in YYMMDDHHMMSSZ format.
 * 3. Certificate revocation date in YYMMDDHHMMSSZ[,reason] format. Empty if not revoked.
 * 4. Certificate serial number in hex.
 * 5. Certificate filename or literal string ‘unknown’.
 * 6. Certificate distinguished name.
 *
 * @author wdawson
 */
public class CertificateSummary {

    @VisibleForTesting
    public static final DateTimeFormatter DATE_TIME_FORMATTER = DateTimeFormat.forPattern("yyMMddHHmmssZ");

    private final CertificateStatus status;
    private final DateTime expirationTime;
    private final DateTime revocationTime;
    private final RevocationReason revocationReason;
    private final BigInteger serialNumber;
    private final String fileName;
    private final X500Principal subjectDN;

    private final DateTime thisUpdateTime;

    public CertificateStatus getStatus() {
        return status;
    }

    public DateTime getExpirationTime() {
        return expirationTime;
    }

    public DateTime getRevocationTime() {
        return revocationTime;
    }

    public RevocationReason getRevocationReason() {
        return revocationReason;
    }

    public BigInteger getSerialNumber() {
        return serialNumber;
    }

    public String getFileName() {
        return fileName;
    }

    public X500Principal getSubjectDN() {
        return subjectDN;
    }

    public DateTime getThisUpdateTime() {
        return thisUpdateTime;
    }

    private CertificateSummary(Builder builder) {
        status = builder.status;
        expirationTime = builder.expirationTime;
        revocationTime = builder.revocationTime;
        revocationReason = builder.revocationReason;
        serialNumber = builder.serialNumber;
        fileName = builder.fileName;
        subjectDN = builder.subjectDN;
        thisUpdateTime = builder.thisUpdateTime == null ? DateTime.now() : builder.thisUpdateTime;
    }

    public static Builder newBuilder() {
        return new Builder();
    }

    public static final class Builder {
        private CertificateStatus status = CertificateStatus.UNKNOWN;
        private DateTime expirationTime = null;
        private DateTime revocationTime = null;
        private RevocationReason revocationReason = null;
        private BigInteger serialNumber = null;
        private String fileName = null;
        private X500Principal subjectDN = null;

        private DateTime thisUpdateTime = null;

        private Builder() {
        }

        public Builder withStatus(CertificateStatus val) {
            status = val;
            return this;
        }

        public Builder withExpirationTime(DateTime val) {
            expirationTime = val;
            return this;
        }

        public Builder withRevocationTime(DateTime val) {
            revocationTime = val;
            return this;
        }

        public Builder withRevocationReason(RevocationReason val) {
            revocationReason = val;
            return this;
        }

        public Builder withSerialNumber(BigInteger val) {
            serialNumber = val;
            return this;
        }

        public Builder withFileName(String val) {
            fileName = val;
            return this;
        }

        public Builder withSubjectDN(X500Principal val) {
            subjectDN = val;
            return this;
        }

        @VisibleForTesting
        public Builder withThisUpdateTime(DateTime val) {
            thisUpdateTime = val;
            return this;
        }

        public CertificateSummary build() {
            return new CertificateSummary(this);
        }
    }

    public static CertificateSummary parseLine(String indexLine) {
        List<String> fields = Splitter.on('\t').splitToList(indexLine);

        // 0 = status
        CertificateStatus status = CertificateStatus.fromString(fields.get(0));

        // 1 = expiration time
        DateTime expirationTime = DATE_TIME_FORMATTER.parseDateTime(fields.get(1));
        if (expirationTime.isBeforeNow() && status != CertificateStatus.REVOKED) { // Sanity check
            status = CertificateStatus.EXPIRED;
        }

        // 2 = revocation time and reason (separated by comma)
        DateTime revocationTime = null;
        RevocationReason revocationReason = null;
        if (StringUtils.isNotEmpty(fields.get(2))) { // Will be empty if not revoked
            List<String> revocation = Splitter.on(',').splitToList(fields.get(2));
            revocationTime = DATE_TIME_FORMATTER.parseDateTime(revocation.get(0));
            if (revocation.size() > 1) { // Could be no reason given
                revocationReason = RevocationReason.fromName(revocation.get(1));
            }
        }

        // 3 = serial number in hex
        BigInteger serialNumber = new BigInteger(fields.get(3), 16);

        // 4 = filename or "unknown"
        String fileName = null;
        if (!fields.get(4).equals("unknown")) {
            fileName = fields.get(4);
        }

        // 5 = DN of certificate
        String dnString = fields.get(5).trim();
        dnString = StringUtils.substringAfter(dnString, "/"); // strip first slash
        dnString = StringUtils.replace(dnString, "/", ", "); // replace remaining slashes with ", " separator
        X500Principal dn = new X500Principal(dnString);

        return CertificateSummary.newBuilder()
                .withStatus(status)
                .withExpirationTime(expirationTime)
                .withRevocationTime(revocationTime)
                .withRevocationReason(revocationReason)
                .withSerialNumber(serialNumber)
                .withFileName(fileName)
                .withSubjectDN(dn)
                .build();
    }
}
