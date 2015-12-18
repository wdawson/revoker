package wdawson.samples.revoker.representations;

import java.util.Date;
import org.joda.time.DateTime;

/**
 * Wrapper around the OCSP CertificateStatus imbued with when this status was determined and
 * when the next update will happen.
 *
 * @author wdawson
 */
public class OCSPCertificateStatusWrapper {

    private org.bouncycastle.cert.ocsp.CertificateStatus certificateStatus;
    private DateTime thisUpdate;
    private DateTime nextUpdate;

    public OCSPCertificateStatusWrapper(org.bouncycastle.cert.ocsp.CertificateStatus certificateStatus,
                                        DateTime thisUpdate,
                                        DateTime nextUpdate) {
        this.certificateStatus = certificateStatus;
        this.thisUpdate = thisUpdate;
        this.nextUpdate = nextUpdate;
    }

    public org.bouncycastle.cert.ocsp.CertificateStatus getCertificateStatus() {
        return certificateStatus;
    }

    public DateTime getThisUpdate() {
        return thisUpdate;
    }

    public Date getThisUpdateDate() {
        return thisUpdate == null ? null : thisUpdate.toDate();
    }

    public DateTime getNextUpdate() {
        return nextUpdate;
    }

    public Date getNextUpdateDate() {
        return nextUpdate == null ? null : nextUpdate.toDate();
    }
}
