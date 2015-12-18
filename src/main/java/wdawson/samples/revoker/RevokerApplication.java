package wdawson.samples.revoker;

import io.dropwizard.Application;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import wdawson.samples.revoker.configuration.CertificateAuthorityConfiguration;
import wdawson.samples.revoker.configuration.OCSPResponderConfiguration;
import wdawson.samples.revoker.configuration.RevokerConfiguration;
import wdawson.samples.revoker.health.CRLHealthCheck;
import wdawson.samples.revoker.health.OCSPHealthCheck;
import wdawson.samples.revoker.managers.CertificateManager;
import wdawson.samples.revoker.parsers.crl.X509CRLMessageBodyWriter;
import wdawson.samples.revoker.parsers.ocsp.OCSPReqMessageBodyReader;
import wdawson.samples.revoker.parsers.ocsp.OCSPRespMessageBodyWriter;
import wdawson.samples.revoker.resources.CRLDistributionPointResource;
import wdawson.samples.revoker.resources.OCSPResponderResource;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

/**
 * Dropwizard Application that implements an OCSP responder and CRL server
 *
 * @author wdawson
 */
public class RevokerApplication extends Application<RevokerConfiguration> {

    @Override
    public String getName() {
        return "ocsp responder";
    }

    @Override
    public void initialize(Bootstrap<RevokerConfiguration> bootstrap) {
        super.initialize(bootstrap);
    }

    @Override
    public void run(RevokerConfiguration configuration, Environment environment) throws Exception {
        // setup certificate manager
        CertificateAuthorityConfiguration caConfiguration = configuration.getCertificateAuthority();
        CertificateManager certificateManager = new CertificateManager(
                caConfiguration.getCaIndexFile(),
                caConfiguration.getCrlFiles(),
                caConfiguration.getRefreshSeconds()
        );
        environment.lifecycle().manage(certificateManager);

        // setup OCSP crypto
        OCSPResponderConfiguration ocspConfiguration = configuration.getOcspResponder();
        KeyStore ocspKeyStore = KeyStore.getInstance(ocspConfiguration.getKeyStoreType());
        ocspKeyStore.load(new FileInputStream(ocspConfiguration.getKeyStorePath()),
                ocspConfiguration.getKeyStorePassphrase().toCharArray());

        String ocspKeyStoreAlias = ocspConfiguration.getKeyStoreAlias();
        Certificate[] ocspCertificateChain = ocspKeyStore.getCertificateChain(ocspKeyStoreAlias);
        X509Certificate[] ocspX509CertificateChain = new X509Certificate[ocspCertificateChain.length];
        for (int i = 0; i < ocspCertificateChain.length; ++i) {
            ocspX509CertificateChain[i] = (X509Certificate) ocspCertificateChain[i];
        }
        PrivateKey ocspSigningKey = (PrivateKey) ocspKeyStore.getKey(ocspKeyStoreAlias,
                ocspConfiguration.getKeyStorePassphrase().toCharArray());

        // setup OCSP resource and healthcheck
        OCSPResponderResource ocspResource = new OCSPResponderResource(
                certificateManager,
                ocspX509CertificateChain,
                ocspSigningKey,
                ocspConfiguration.isRejectUnknown()
        );
        OCSPHealthCheck ocspHealthCheck = new OCSPHealthCheck(
                certificateManager,
                ocspX509CertificateChain
        );

        environment.jersey().register(ocspResource);
        environment.healthChecks().register("OCSP", ocspHealthCheck);
        environment.jersey().register(OCSPReqMessageBodyReader.class);
        environment.jersey().register(OCSPRespMessageBodyWriter.class);

        // setup CRL resource and healthcheck
        CRLDistributionPointResource crlResource = new CRLDistributionPointResource(
                certificateManager
        );
        CRLHealthCheck crlHealthCheck = new CRLHealthCheck(
                caConfiguration.getCrlFiles()
        );

        environment.jersey().register(crlResource);
        environment.healthChecks().register("CRL", crlHealthCheck);
        environment.jersey().register(X509CRLMessageBodyWriter.class);
    }

    public static void main(String[] args) throws Exception {
        new RevokerApplication().run(args);
    }
}
