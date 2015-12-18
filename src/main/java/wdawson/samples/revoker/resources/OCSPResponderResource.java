package wdawson.samples.revoker.resources;

import com.codahale.metrics.annotation.Timed;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.GET;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.UrlBase64;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import wdawson.samples.revoker.managers.CertificateManager;
import wdawson.samples.revoker.representations.CertificateSummary;
import wdawson.samples.revoker.representations.OCSPCertificateStatusWrapper;

import static wdawson.samples.revoker.representations.RevocationReason.SUPERSEDED;
import static wdawson.samples.revoker.representations.RevocationReason.UNSPECIFIED;

/**
 * Resource for handling OCSP
 *
 * @author wdawson
 */
@Path("/ocsp")
@Produces("application/ocsp-response")
public class OCSPResponderResource {
    private static final Logger LOG = LoggerFactory.getLogger(OCSPResponderResource.class);

    // Configuration
    private X509CertificateHolder issuingCertificate;
    private X509CertificateHolder[] signingCertificateChain;
    private boolean rejectUnknown;

    // Services
    private CertificateManager certificateManager;

    // Cached objects to use
    private RespID responderID;
    private DigestCalculatorProvider digestCalculatorProvider;
    private ContentSigner contentSigner;


    public OCSPResponderResource(CertificateManager certificateManager,
                                 X509Certificate[] signingCertificateChain,
                                 PrivateKey signingKey,
                                 boolean rejectUnknown) {
        Security.addProvider(new BouncyCastleProvider()); // Can be found via its name "BC" later

        this.certificateManager = certificateManager;

        // Parse certificates into Bouncy Castle formats
        this.signingCertificateChain = new X509CertificateHolder[signingCertificateChain.length];
        for (int i = 0; i < signingCertificateChain.length; ++i) {
            try {
                this.signingCertificateChain[i] = new JcaX509CertificateHolder(signingCertificateChain[i]);
            } catch (CertificateEncodingException e) {
                throw new IllegalArgumentException("Could not parse signing certificate at position " + i);
            }
        }
        this.issuingCertificate = this.signingCertificateChain[1];

        this.rejectUnknown = rejectUnknown;

        // Get responder ID
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(
                signingCertificateChain[0].getPublicKey().getEncoded()
        );
        try {
            this.digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder()
                    .setProvider("BC")
                    .build();
            responderID = new RespID(
                    publicKeyInfo,
                    // only SHA-1 support with RespID :(
                    digestCalculatorProvider.get(new DefaultDigestAlgorithmIdentifierFinder().find("SHA-1"))
            );
        } catch (OperatorCreationException | OCSPException e) {
            throw new IllegalArgumentException("Could not build responder ID", e);
        }

        // Setup Content Signer
        try {
            contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider("BC")
                    .build(signingKey);
        } catch (OperatorCreationException e) {
            throw new IllegalArgumentException("Could not build contentSigner", e);
        }
    }

    /**
     * OCSP request over HTTP via GET.
     *
     * This method will parse the param and return a 400 if it could not.
     *
     * @param urlEncodedOCSPRequest The url-safe, base64 encoded, der encoded, OCSP request
     * @return The OCSP response
     * @throws BadRequestException If the OCSP request was malformed.
     */
    @GET
    @Path("/{urlEncodedOCSPRequest}")
    @Timed
    public OCSPResp processGetRequest(@PathParam("urlEncodedOCSPRequest") String urlEncodedOCSPRequest) {
        OCSPReq ocspReq;
        try {
            byte[] derEncodedOCSPRequest;
            try {
                derEncodedOCSPRequest = UrlBase64.decode(urlEncodedOCSPRequest);
            } catch (DecoderException e) {
                throw new BadRequestException("Could not decode url safe base 64 encoded ocsp request",
                        Response.status(Response.Status.BAD_REQUEST).entity(
                                new OCSPRespBuilder().build(OCSPRespBuilder.MALFORMED_REQUEST, null)
                        ).build(),
                        e);
            }

            try {
                ocspReq = new OCSPReq(derEncodedOCSPRequest);
            } catch (IOException e) {
                throw new BadRequestException("Could not parse OCSP request",
                        Response.status(Response.Status.BAD_REQUEST).entity(
                                new OCSPRespBuilder().build(OCSPRespBuilder.MALFORMED_REQUEST, null)
                        ).build(),
                        e);
            }
        } catch (OCSPException e) {
            throw new InternalServerErrorException("Could not construct proper OCSP response", e);
        }

        return processOCSPRequest(ocspReq);
    }

    /**
     * OCSP request over HTTP via POST
     *
     * @param ocspReq The OCSP request
     * @return The OCSP response
     */
    @POST
    @Timed
    public OCSPResp processPostRequest(OCSPReq ocspReq) {
        return processOCSPRequest(ocspReq);
    }

    /**
     * Processes the OCSP request and catches any exceptions that occur to attempt to
     * return an INTERNAL_ERROR response. If it still can't do that, 500s.
     *
     * @param ocspReq The OCSP request
     * @return The OCSP response if possible
     * @throws InternalServerErrorException if returning a proper OCSP response is not possible
     */
    private OCSPResp processOCSPRequest(OCSPReq ocspReq) {
        try {
            return doProcessOCSPRequest(ocspReq);
        } catch (OCSPException e) {
            try {
                // Try making an internal error response as a last ditch attempt.
                LOG.error("Error processing OCSP Request!", e);
                throw new InternalServerErrorException("Error processing OCSP Request",
                        Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(
                                new OCSPRespBuilder().build(OCSPRespBuilder.INTERNAL_ERROR, null)
                        ).build(),
                        e);
            } catch (OCSPException e1) {
                LOG.error("Could not return a response!", e1);
                throw new InternalServerErrorException("Could not build proper response", e1);
            }
        }
    }

    /**
     * Processes the OCSP request from the client.
     *
     * According to <a href="https://tools.ietf.org/html/rfc6960">RFC 6960 </a> the responder
     * is tasked with the following checks and if any are not true, an error message is returned:
     *
     * 1. the message is well formed
     * 2. the responder is configured to provide the requested service
     * 3. the request contains the information needed by the responder.
     *
     * If we are at this point, number one is taken care of (we were able to parse it).
     *
     * This method will check the second and third conditions as well as do any additional
     * validation on the request before returning an OCSP response.
     *
     * @param ocspReq The OCSP request
     * @return The OCSP response
     */
    private OCSPResp doProcessOCSPRequest(OCSPReq ocspReq) throws OCSPException {
        BasicOCSPRespBuilder responseBuilder = new BasicOCSPRespBuilder(responderID);

        checkForValidRequest(ocspReq);

        // Add appropriate extensions
        Collection<Extension> responseExtensions = new ArrayList<>();
        //nonce
        Extension nonceExtension = ocspReq.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        if (nonceExtension != null) {
            responseExtensions.add(nonceExtension);
        }
        if (rejectUnknown) {
            responseExtensions.add(
                    new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_extended_revoke, false, new byte[]{})
            );
        }

        Extension[] extensions = responseExtensions.toArray(new Extension[responseExtensions.size()]);
        responseBuilder.setResponseExtensions(new Extensions(extensions));

        // Check that each request is valid and put the appropriate response in the builder
        Req[] requests = ocspReq.getRequestList();
        for (Req request : requests) {
            addResponse(responseBuilder, request);
        }
        return buildAndSignResponse(responseBuilder);
    }

    /**
     * Checks for a valid request and throws a BadRequestException with the OCSP response if not valid
     *
     * @param ocspReq The request
     * @throws BadRequestException with the OCSP response if the request was malformed
     */
    private void checkForValidRequest(OCSPReq ocspReq) throws OCSPException {
        if (ocspReq == null) {
            throw new BadRequestException("Could not find a request in the payload!",
                    Response.status(Response.Status.BAD_REQUEST).entity(
                            new OCSPRespBuilder().build(OCSPRespBuilder.MALFORMED_REQUEST, null)
                    ).build()
            );
        }
        // Check signature if present
        if (ocspReq.isSigned() && !isSignatureValid(ocspReq)) {
            throw new BadRequestException("Your signature was invalid!",
                    Response.status(Response.Status.BAD_REQUEST).entity(
                            new OCSPRespBuilder().build(OCSPRespBuilder.MALFORMED_REQUEST, null)
                    ).build()
            );
        }
    }

    /**
     * Checks to see if the signature in the OCSP request is valid.
     *
     * @param ocspReq The OCSP request.
     * @return {@code true} if the signature is valid, {@code false} otherwise.
     */
    private boolean isSignatureValid(OCSPReq ocspReq) throws OCSPException {
        try {
            return ocspReq.isSignatureValid(
                    new JcaContentVerifierProviderBuilder() // Can we reuse this builder?
                            .setProvider("BC")
                            .build(ocspReq.getCerts()[0])
            );
        } catch (CertificateException | OperatorCreationException e) {
            LOG.warn("Could not read signature!", e);
            return false;
        }
    }

    /**
     * Adds response for specific cert OCSP request
     *
     * @param responseBuilder The builder containing the full response
     * @param request The specific cert request
     */
    private void addResponse(BasicOCSPRespBuilder responseBuilder, Req request) throws OCSPException{
        CertificateID certificateID = request.getCertID();

        // Build Extensions
        Extensions extensions = new Extensions(new Extension[]{});
        Extensions requestExtensions = request.getSingleRequestExtensions();
        if (requestExtensions != null) {
            Extension nonceExtension = requestExtensions.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            if (nonceExtension != null) {
                extensions = new Extensions(nonceExtension);
            }
        }

        // Check issuer
        boolean matchesIssuer = certificateID.matchesIssuer(issuingCertificate, digestCalculatorProvider);

        if (!matchesIssuer) {
            addResponseForCertificateRequest(responseBuilder,
                    certificateID,
                    new OCSPCertificateStatusWrapper(getUnknownStatus(),
                            DateTime.now(),
                            DateTime.now().plusSeconds(certificateManager.getRefreshSeconds())),
                    extensions);

        } else {
            CertificateSummary certificateSummary = certificateManager.getSummary(certificateID.getSerialNumber());

            addResponseForCertificateRequest(responseBuilder,
                    request.getCertID(),
                    getOCSPCertificateStatus(certificateSummary),
                    extensions);
        }
    }

    private void addResponseForCertificateRequest(BasicOCSPRespBuilder responseBuilder,
                                           CertificateID certificateID,
                                           OCSPCertificateStatusWrapper status,
                                           Extensions extensions) {
        responseBuilder.addResponse(certificateID,
                status.getCertificateStatus(),
                status.getThisUpdateDate(),
                status.getNextUpdateDate(),
                extensions);
    }

    /**
     * Gets the OCSP Certificate Status Wrapper with the Certificate Status (good, revoked, unknown),
     * the updated date, and the next update date.
     *
     * @param summary The certificate summary
     * @return The status wrapper
     */
    private OCSPCertificateStatusWrapper getOCSPCertificateStatus(CertificateSummary summary) {
        CertificateStatus status;
        switch (summary.getStatus()) {
            case VALID:
                status = CertificateStatus.GOOD;
                break;
            case REVOKED:
                status = new RevokedStatus(summary.getRevocationTime().toDate(), summary.getRevocationReason().getCode());
                break;
            case EXPIRED:
                status = new RevokedStatus(summary.getExpirationTime().toDate(), SUPERSEDED.getCode());
                break;
            case UNKNOWN:
                status = getUnknownStatus();
                break;
            default:
                throw new IllegalArgumentException("Unknown status! " + summary.getStatus().name());
        }
        DateTime updateTime = summary.getThisUpdateTime();
        return new OCSPCertificateStatusWrapper(status,
                updateTime,
                updateTime.plusSeconds(certificateManager.getRefreshSeconds())
        );
    }

    /**
     * Gets the unknown CertificateStatus to return depending on the value of {@code rejectUnknown}
     *
     * @return The CertificateStatus to use for unknown certificates
     */
    private CertificateStatus getUnknownStatus() {
        if (rejectUnknown) {
            return new RevokedStatus(DateTime.now().toDate(), UNSPECIFIED.getCode());
        } else {
            return new UnknownStatus();
        }
    }

    /**
     * Builds and signs the response in the builder
     *
     * @param responseBuilder The builder
     * @return The signed response
     */
    private OCSPResp buildAndSignResponse(BasicOCSPRespBuilder responseBuilder) throws OCSPException {
        BasicOCSPResp basicResponse = responseBuilder.build(
                contentSigner,
                signingCertificateChain,
                new Date()
        );
        return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basicResponse);
    }
}
