package wdawson.samples.revoker.parsers.crl;

import java.io.IOException;
import java.io.InputStream;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.Consumes;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.ext.MessageBodyReader;
import javax.ws.rs.ext.Provider;

/**
 * @author wdawson
 */
@Provider
@Consumes("application/pkix-crl")
public class X509CRLMessageBodyReader implements MessageBodyReader<X509CRL> {

    private static CertificateFactory CERTIFICATE_FACTORY;

    public X509CRLMessageBodyReader() {
        try {
            CERTIFICATE_FACTORY = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new IllegalStateException("Could not get X.509 instance of certificate factory", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isReadable(Class<?> type,
                              Type genericType,
                              Annotation[] annotations,
                              MediaType mediaType) {
        return X509CRL.class.isAssignableFrom(type);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public X509CRL readFrom(Class<X509CRL> type,
                            Type genericType,
                            Annotation[] annotations,
                            MediaType mediaType,
                            MultivaluedMap<String, String> httpHeaders,
                            InputStream entityStream) throws IOException, WebApplicationException {
        try {
            return (X509CRL) CERTIFICATE_FACTORY.generateCRL(entityStream);
        } catch (CRLException e) {
            throw new BadRequestException("Could not read CRL", e);
        }
    }
}
