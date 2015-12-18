package wdawson.samples.revoker.resources;

import com.codahale.metrics.annotation.Timed;
import java.security.cert.X509CRL;
import javax.ws.rs.GET;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import wdawson.samples.revoker.managers.CertificateManager;

/**
 * Resource that acts as a CRL Distribution Point
 *
 * @author wdawson
 */
@Path("/crls")
@Produces("application/pkix-crl")
public class CRLDistributionPointResource {

    private CertificateManager certificateManager;

    public CRLDistributionPointResource(CertificateManager certificateManager) {
        this.certificateManager = certificateManager;
    }

    @GET
    @Timed
    @Path("/{crlName}")
    public X509CRL getCRL(@PathParam("crlName") String crlName) {
        X509CRL crl =  certificateManager.getCRL(crlName);
        if (crl == null) {
            throw new NotFoundException("CRL for " + crlName + " not found");
        } else {
            return crl;
        }
    }
}
