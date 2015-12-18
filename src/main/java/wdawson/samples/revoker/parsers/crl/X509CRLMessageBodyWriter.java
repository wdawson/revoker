package wdawson.samples.revoker.parsers.crl;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.ext.MessageBodyWriter;
import javax.ws.rs.ext.Provider;

/**
 * @author wdawson
 */
@Provider
@Produces("application/pkix-crl")
public class X509CRLMessageBodyWriter implements MessageBodyWriter<X509CRL> {

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isWriteable(Class<?> type,
                               Type genericType,
                               Annotation[] annotations,
                               MediaType mediaType) {
        return X509CRL.class.isAssignableFrom(type);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public long getSize(X509CRL x509CRL,
                        Class<?> type,
                        Type genericType,
                        Annotation[] annotations,
                        MediaType mediaType) {
        // deprecated by JAX-RS 2.0 and ignored by Jersey runtime
        return -1;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void writeTo(X509CRL x509CRL,
                        Class<?> type,
                        Type genericType,
                        Annotation[] annotations,
                        MediaType mediaType,
                        MultivaluedMap<String, Object> httpHeaders,
                        OutputStream entityStream) throws IOException, WebApplicationException {
        try {
            entityStream.write(x509CRL.getEncoded());
        } catch (CRLException e) {
            throw new InternalServerErrorException("Could not write CRL to response!", e);
        }
    }
}
