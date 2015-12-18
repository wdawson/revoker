package wdawson.samples.revoker.resources;

import com.google.common.collect.Lists;
import com.google.common.io.Resources;
import io.dropwizard.testing.junit.ResourceTestRule;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.NotAllowedException;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Response;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.encoders.UrlBase64;
import org.joda.time.DateTime;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import wdawson.samples.revoker.managers.CertificateManager;
import wdawson.samples.revoker.parsers.ocsp.OCSPReqMessageBodyReader;
import wdawson.samples.revoker.parsers.ocsp.OCSPReqMessageBodyWriter;
import wdawson.samples.revoker.parsers.ocsp.OCSPRespMessageBodyReader;
import wdawson.samples.revoker.parsers.ocsp.OCSPRespMessageBodyWriter;
import wdawson.samples.revoker.representations.CertificateStatus;
import wdawson.samples.revoker.representations.CertificateSummary;
import wdawson.samples.revoker.representations.OCSPCertificateStatusWrapper;
import wdawson.samples.revoker.representations.RevocationReason;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.failBecauseExceptionWasNotThrown;
import static org.bouncycastle.cert.ocsp.CertificateStatus.GOOD;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static wdawson.samples.revoker.representations.RevocationReason.SUPERSEDED;

/**
 * @author wdawson
 */
public class OCSPResponderResourceTest {

    private final static DateTime NOW = DateTime.now().withMillisOfSecond(0);
    private final static DateTime EXPIRE = NOW.plusYears(1);
    private final static DateTime REVOKE = NOW.minusDays(3);

    private final static BigInteger ONE   = BigInteger.valueOf(1L);
    private final static BigInteger TWO   = BigInteger.valueOf(2L);
    private final static BigInteger THREE = BigInteger.valueOf(3L);
    private final static BigInteger FOUR  = BigInteger.valueOf(4L);

    private final CertificateSummary validCert = CertificateSummary.newBuilder()
            .withStatus(CertificateStatus.VALID)
            .withExpirationTime(EXPIRE)
            .withSerialNumber(ONE)
            .withThisUpdateTime(NOW)
            .build();

    private final CertificateSummary revokedCert = CertificateSummary.newBuilder()
            .withStatus(CertificateStatus.REVOKED)
            .withExpirationTime(EXPIRE)
            .withRevocationTime(REVOKE)
            .withRevocationReason(RevocationReason.KEY_COMPROMISE)
            .withSerialNumber(TWO)
            .withThisUpdateTime(NOW)
            .build();

    private final CertificateSummary expiredCert = CertificateSummary.newBuilder()
            .withStatus(CertificateStatus.EXPIRED)
            .withExpirationTime(EXPIRE)
            .withRevocationTime(null)
            .withRevocationReason(null)
            .withSerialNumber(THREE)
            .withThisUpdateTime(NOW)
            .build();

    private final CertificateSummary unknownCert = CertificateSummary.newBuilder()
            .withStatus(CertificateStatus.UNKNOWN)
            .withSerialNumber(FOUR)
            .withThisUpdateTime(NOW)
            .build();

    private static final CertificateManager certificateManager = mock(CertificateManager.class);
    private static final int REFRESH_TIME = 4;

    private static X509CertificateHolder[] signingCertificateChain;
    private static X509Certificate issuingCertificate;
    private static X509Certificate signingCertificate;
    private static PrivateKey signingKey;

    @ClassRule
    public static final ResourceTestRule resources = ResourceTestRule.builder()
            .addResource(new OCSPResponderResource(
                    certificateManager,
                    loadSigningCertificateChain(),
                    loadSigningKey(),
                    false
            ))
            .addProvider(OCSPReqMessageBodyReader.class)
            .addProvider(OCSPRespMessageBodyWriter.class)
            .build();

    @BeforeClass
    public static void setupClass() {
        Security.addProvider(new BouncyCastleProvider());

        // Register OCSP providers for the client too
        resources.client()
                .register(OCSPReqMessageBodyWriter.class)
                .register(OCSPRespMessageBodyReader.class);
    }

    @Before
    public void setup() {
        when(certificateManager.getRefreshSeconds()).thenReturn(REFRESH_TIME);
    }

    @After
    public void teardown() {
        reset(certificateManager);
    }

    @Test
    public void getWithNoDataIsNotAllowed() {
        try {
            resources.client().target("/ocsp/").request().get(OCSPResp.class);
            failBecauseExceptionWasNotThrown(NotAllowedException.class);
        } catch (NotAllowedException e) {
            assertThat(e).hasMessageEndingWith("HTTP 405 Method Not Allowed");
        }
    }

    @Test
    public void getWithBadDataIsMalformed() throws Exception {
        try {
            resources.client().target("/ocsp/").path("BAD_DATA").request().get(OCSPResp.class);
            failBecauseExceptionWasNotThrown(BadRequestException.class);
        } catch (BadRequestException e) {
            assertThat(e).hasMessageEndingWith("HTTP 400 Bad Request");
            Response response = e.getResponse();
            assertThat(response.hasEntity()).isTrue();
            assertThat(response.getEntity()).isInstanceOf(InputStream.class);

            OCSPResp ocspResp = new OCSPResp((InputStream) response.getEntity());
            assertThat(ocspResp.getStatus()).isEqualTo(OCSPRespBuilder.MALFORMED_REQUEST);
            assertThat(ocspResp.getResponseObject()).isNull();
        }
    }

    @Test
    public void getWithUnsignedValidCertReturnsSuccessfulResponse() throws Exception {
        OCSPReq ocspReq = buildUnsignedOCSPRequest(validCert.getSerialNumber());
        String payload = new String(UrlBase64.encode(ocspReq.getEncoded()));

        when(certificateManager.getSummary(validCert.getSerialNumber())).thenReturn(validCert);

        OCSPResp ocspResp = resources.client().target("/ocsp/").path(payload).request().get(OCSPResp.class);

        validateSuccessfulResponse(ocspResp, ocspReq, validCert);

        verify(certificateManager).getSummary(validCert.getSerialNumber());
    }

    @Test
    public void getWithSignedValidCertReturnsSuccessfulResponse() throws Exception {
        OCSPReq ocspReq = buildSignedOCSPRequest(validCert.getSerialNumber());
        String payload = new String(UrlBase64.encode(ocspReq.getEncoded()));

        when(certificateManager.getSummary(validCert.getSerialNumber())).thenReturn(validCert);

        OCSPResp ocspResp = resources.client().target("/ocsp/").path(payload).request().get(OCSPResp.class);

        validateSuccessfulResponse(ocspResp, ocspReq, validCert);

        verify(certificateManager).getSummary(validCert.getSerialNumber());
    }

    @Test
    public void postWithNoPayloadIsMalformed() throws Exception {
        try {
            resources.client().target("/ocsp/").request().post(null, OCSPResp.class);
        } catch (BadRequestException e) {
            assertThat(e).hasMessageEndingWith("HTTP 400 Bad Request");
            Response response = e.getResponse();
            assertThat(response.hasEntity()).isTrue();
            assertThat(response.getEntity()).isInstanceOf(InputStream.class);

            OCSPResp ocspResp = new OCSPResp((InputStream) response.getEntity());
            assertThat(ocspResp.getStatus()).isEqualTo(OCSPRespBuilder.MALFORMED_REQUEST);
            assertThat(ocspResp.getResponseObject()).isNull();
        }
    }

    @Test
    public void postWithBadPayloadIsMalformed() throws Exception {
        try {
            resources.client().target("/ocsp/").request()
                    .post(Entity.entity("BAD_DATA", "application/ocsp-request"), OCSPResp.class);
        } catch (BadRequestException e) {
            assertThat(e).hasMessageEndingWith("HTTP 400 Bad Request");
            Response response = e.getResponse();
            assertThat(response.hasEntity()).isTrue();
            assertThat(response.getEntity()).isInstanceOf(InputStream.class);

            OCSPResp ocspResp = new OCSPResp((InputStream) response.getEntity());
            assertThat(ocspResp.getStatus()).isEqualTo(OCSPRespBuilder.MALFORMED_REQUEST);
            assertThat(ocspResp.getResponseObject()).isNull();
        }
    }

    @Test
    public void postWithUnsignedValidCertReturnsSuccessfulResponse() throws Exception {
        OCSPReq ocspReq = buildUnsignedOCSPRequest(validCert.getSerialNumber());

        when(certificateManager.getSummary(validCert.getSerialNumber())).thenReturn(validCert);

        OCSPResp ocspResp = resources.client().target("/ocsp/").request()
                .post(Entity.entity(ocspReq, "application/ocsp-request"), OCSPResp.class);

        validateSuccessfulResponse(ocspResp, ocspReq, validCert);

        verify(certificateManager).getSummary(validCert.getSerialNumber());
    }

    @Test
    public void postWithSignedValidCertReturnsSuccessfulResponse() throws Exception {
        OCSPReq ocspReq = buildSignedOCSPRequest(validCert.getSerialNumber());

        when(certificateManager.getSummary(validCert.getSerialNumber())).thenReturn(validCert);

        OCSPResp ocspResp = resources.client().target("/ocsp/").request()
                .post(Entity.entity(ocspReq, "application/ocsp-request"), OCSPResp.class);

        validateSuccessfulResponse(ocspResp, ocspReq, validCert);

        verify(certificateManager).getSummary(validCert.getSerialNumber());
    }

    @Test
    public void postWithSignedRevokedCertReturnsSuccessfulResponse() throws Exception {
        OCSPReq ocspReq = buildSignedOCSPRequest(revokedCert.getSerialNumber());

        when(certificateManager.getSummary(revokedCert.getSerialNumber())).thenReturn(revokedCert);

        OCSPResp ocspResp = resources.client().target("/ocsp/").request()
                .post(Entity.entity(ocspReq, "application/ocsp-request"), OCSPResp.class);

        validateSuccessfulResponse(ocspResp, ocspReq, revokedCert);

        verify(certificateManager).getSummary(revokedCert.getSerialNumber());
    }

    @Test
    public void postWithSignedExpiredCertReturnsSuccessfulResponse() throws Exception {
        OCSPReq ocspReq = buildSignedOCSPRequest(expiredCert.getSerialNumber());

        when(certificateManager.getSummary(expiredCert.getSerialNumber())).thenReturn(expiredCert);

        OCSPResp ocspResp = resources.client().target("/ocsp/").request()
                .post(Entity.entity(ocspReq, "application/ocsp-request"), OCSPResp.class);

        validateSuccessfulResponse(ocspResp, ocspReq, expiredCert);

        verify(certificateManager).getSummary(expiredCert.getSerialNumber());
    }

    @Test
    public void postWithSignedUnknownCertReturnsSuccessfulResponse() throws Exception {
        OCSPReq ocspReq = buildSignedOCSPRequest(unknownCert.getSerialNumber());

        when(certificateManager.getSummary(unknownCert.getSerialNumber())).thenReturn(unknownCert);

        OCSPResp ocspResp = resources.client().target("/ocsp/").request()
                .post(Entity.entity(ocspReq, "application/ocsp-request"), OCSPResp.class);

        validateSuccessfulResponse(ocspResp, ocspReq, unknownCert);

        verify(certificateManager).getSummary(unknownCert.getSerialNumber());
    }

    /* Response Checkers */

    private void validateSuccessfulResponse(OCSPResp ocspResp,
                                            OCSPReq ocspReq,
                                            CertificateSummary... summaries) throws Exception {
        assertThat(summaries).isNotEmpty();

        assertThat(ocspResp.getStatus()).isEqualTo(OCSPRespBuilder.SUCCESSFUL);
        assertThat(ocspResp.getResponseObject()).isExactlyInstanceOf(BasicOCSPResp.class);
        BasicOCSPResp basicResponse = (BasicOCSPResp)ocspResp.getResponseObject();
        assertThat(basicResponse.getProducedAt()).isAfterOrEqualsTo(NOW.toDate());

        // check signature
        boolean validSignature = basicResponse.isSignatureValid(
                new JcaContentVerifierProviderBuilder().setProvider("BC").build(signingCertificate.getPublicKey()));
        assertThat(validSignature).isTrue().withFailMessage("Signature was invalid");
        assertThat(basicResponse.getSignatureAlgorithmID()).isEqualTo(
                new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA")
        );

        // check extensions
        List<ASN1ObjectIdentifier> extensionOIDs = Lists.transform(
                (List<?>) basicResponse.getExtensionOIDs(),
                input -> (ASN1ObjectIdentifier) input  // just casting here
        );
        assertThat(extensionOIDs).containsExactly(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);

        Extension reqNonce = ocspReq.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        Extension respNonce = basicResponse.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        assertThat(respNonce).isEqualTo(reqNonce);

        SingleResp[] singleResponses = basicResponse.getResponses();
        Req[] singleRequests = ocspReq.getRequestList();
        assertThat(singleResponses).hasSameSizeAs(singleRequests);

        for (int i = 0; i < singleRequests.length; i++) {
            Req request = singleRequests[i];
            SingleResp response = singleResponses[i];

            assertThat(response.getCertID()).isEqualTo(request.getCertID());

            ASN1ObjectIdentifier[] requestExtensions = request.getSingleRequestExtensions().getExtensionOIDs();
            for (ASN1ObjectIdentifier extensionOID : requestExtensions) {
                Extension extension = response.getExtension(extensionOID);
                assertThat(extension).isNotNull();
                assertThat(extension).isEqualTo(request.getSingleRequestExtensions().getExtension(extensionOID));
            }

            assertThat(response.getCertID().getSerialNumber()).isEqualTo(summaries[i].getSerialNumber());
            org.bouncycastle.cert.ocsp.CertificateStatus ocspCertificateStatus =
                    getOCSPCertificateStatus(summaries[i]).getCertificateStatus();
            if (ocspCertificateStatus == GOOD) {
                assertThat(response.getCertStatus()).isEqualTo(GOOD); // They implemented GOOD as null ... really? .....
            } else {
                assertThat(response.getCertStatus()).isEqualToComparingFieldByField(ocspCertificateStatus);
            }

            assertThat(response.getThisUpdate()).isEqualToIgnoringMillis(summaries[i].getThisUpdateTime().toDate());
            assertThat(response.getNextUpdate())
                    .hasSecond((summaries[i].getThisUpdateTime().getSecondOfMinute() + REFRESH_TIME) % 60);
        }
    }

    /* Request Builders */

    private OCSPReq buildSignedOCSPRequest(BigInteger serialNumber) throws Exception {
        return getOCSPReqBuilder(serialNumber)
                .setRequestorName(X500Name.getInstance(signingCertificate.getSubjectX500Principal().getEncoded()))
                .build(new JcaContentSignerBuilder("SHA256withRSA")
                                .setProvider("BC")
                                .build(signingKey),
                        signingCertificateChain
                );
    }

    private OCSPReq buildUnsignedOCSPRequest(BigInteger serialNumber) throws Exception {
        return getOCSPReqBuilder(serialNumber).build();
    }

    private OCSPReqBuilder getOCSPReqBuilder(BigInteger serialNumber) throws Exception {
        // Generate the id for the certificate we are looking for
        CertificateID id = new CertificateID(
                new JcaDigestCalculatorProviderBuilder().setProvider("BC").build().get(CertificateID.HASH_SHA1),
                new X509CertificateHolder(issuingCertificate.getEncoded()),
                serialNumber
        );

        OCSPReqBuilder requestBuilder = new OCSPReqBuilder();

        requestBuilder.addRequest(id, new Extensions(new Extension[] { buildNonceExtension() }));

        // create nonce extension
        requestBuilder.setRequestExtensions(new Extensions(new Extension[] { buildNonceExtension() }));

        return requestBuilder;
    }

    private Extension buildNonceExtension() {
        BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
        return new Extension(
                OCSPObjectIdentifiers.id_pkix_ocsp_nonce,
                true,
                new DEROctetString(nonce.toByteArray())
        );
    }

    /* Random Helpers */

    private OCSPCertificateStatusWrapper getOCSPCertificateStatus(CertificateSummary summary) {
        org.bouncycastle.cert.ocsp.CertificateStatus status;
        switch (summary.getStatus()) {
            case VALID:
                status = GOOD;
                break;
            case REVOKED:
                status = new RevokedStatus(summary.getRevocationTime().toDate(), summary.getRevocationReason().getCode());
                break;
            case EXPIRED:
                status = new RevokedStatus(summary.getExpirationTime().toDate(), SUPERSEDED.getCode());
                break;
            case UNKNOWN:
                status = new UnknownStatus();
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

    /* Crypto Helpers */

    // NOTE: We initialize the static class variables here since these are called by the static Rule builder.
    //       We can't initialize them when we declare them since the keystore load throws a checked exception.
    private static X509Certificate[] loadSigningCertificateChain() {
        KeyStore keyStore = loadKeyStore();

        try {
            Certificate[] certificateChain = keyStore.getCertificateChain("ocsp-signing");
            X509Certificate[] x509CertificateChain = new X509Certificate[certificateChain.length];
            for (int i = 0; i < certificateChain.length; ++i) {
                x509CertificateChain[i] = (X509Certificate) certificateChain[i];
            }
            signingCertificate = x509CertificateChain[0];
            issuingCertificate = x509CertificateChain[1];
            signingCertificateChain = new X509CertificateHolder[certificateChain.length];
            for (int i = 0; i < signingCertificateChain.length; ++i) {
                signingCertificateChain[i] = new JcaX509CertificateHolder(x509CertificateChain[i]);
            }

            return x509CertificateChain;
        } catch (KeyStoreException | CertificateEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    private static PrivateKey loadSigningKey() {
        KeyStore keyStore = loadKeyStore();

        try {
            return signingKey = (PrivateKey) keyStore.getKey("ocsp-signing", "notsecret".toCharArray());
        } catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static KeyStore loadKeyStore() {
        try {
            KeyStore ocspKeyStore = KeyStore.getInstance("JKS");
            ocspKeyStore.load(Resources.getResource("ocsp/ocsp-signing.jks").openStream(), "notsecret".toCharArray());
            return ocspKeyStore;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }
}
