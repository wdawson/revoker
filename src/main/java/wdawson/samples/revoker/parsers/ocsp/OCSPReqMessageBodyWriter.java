package wdawson.samples.revoker.parsers.ocsp;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.ext.MessageBodyWriter;
import javax.ws.rs.ext.Provider;
import org.bouncycastle.cert.ocsp.OCSPReq;

/**
 * Handles writing {@link OCSPReq} objects
 *
 * @author wdawson
 */
@Provider
@Produces("application/ocsp-request")
public class OCSPReqMessageBodyWriter implements MessageBodyWriter<OCSPReq> {

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isWriteable(Class<?> type,
                               Type genericType,
                               Annotation[] annotations,
                               MediaType mediaType) {
        return type == OCSPReq.class;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public long getSize(OCSPReq ocspReq,
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
    public void writeTo(OCSPReq ocspReq,
                        Class<?> type, Type genericType,
                        Annotation[] annotations,
                        MediaType mediaType,
                        MultivaluedMap<String, Object> httpHeaders,
                        OutputStream entityStream) throws IOException, WebApplicationException {
        byte[] encodedBytes = ocspReq.getEncoded();
        entityStream.write(encodedBytes);
    }
}
