package wdawson.samples.revoker.resources;

import io.dropwizard.testing.junit.ResourceTestRule;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import javax.ws.rs.NotFoundException;
import org.junit.After;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import wdawson.samples.revoker.managers.CertificateManager;
import wdawson.samples.revoker.parsers.crl.X509CRLMessageBodyReader;
import wdawson.samples.revoker.parsers.crl.X509CRLMessageBodyWriter;

import static io.dropwizard.testing.ResourceHelpers.resourceFilePath;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.failBecauseExceptionWasNotThrown;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * @author wdawson
 */
public class CRLDistributionPointResourceTest {

    private static CertificateFactory certificateFactory;

    private static final CertificateManager certificateManager = mock(CertificateManager.class);

    @ClassRule
    public static final ResourceTestRule resources = ResourceTestRule.builder()
            .addResource(new CRLDistributionPointResource(
                    certificateManager
            ))
            .addProvider(X509CRLMessageBodyWriter.class)
            .build();

    @BeforeClass
    public static void setupClass() throws Exception {
        certificateFactory = CertificateFactory.getInstance("X.509");
        // Register X509 providers for the client too
        resources.client()
                .register(X509CRLMessageBodyReader.class);
    }

    @After
    public void teardown() {
        reset(certificateManager);
    }

    @Test
    public void testThatBadCRLIsNotFound() {
        when(certificateManager.getCRL("BAD_CRL.pem")).thenReturn(null);

        try {
            resources.client().target("/crls").path("/BAD_CRL.pem").request().get(X509CRL.class);
            failBecauseExceptionWasNotThrown(NotFoundException.class);
        } catch (NotFoundException e) {
            assertThat(e).hasMessageEndingWith("HTTP 404 Not Found");
        }

        verify(certificateManager).getCRL("BAD_CRL.pem");
    }

    @Test
    public void testThatValidCRLIsFoundAndReturned() throws Exception {
        InputStream crlStream = new FileInputStream(resourceFilePath("crl/crl.pem"));
        X509CRL expected = (X509CRL) certificateFactory.generateCRL(crlStream);
        when(certificateManager.getCRL("crl.pem")).thenReturn(expected);

        X509CRL response = resources.client().target("/crls").path("/crl.pem").request().get(X509CRL.class);
        assertThat(response).isEqualTo(expected);
    }
}
