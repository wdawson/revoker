package wdawson.samples.revoker.parsers.ocsp;

import org.bouncycastle.cert.ocsp.OCSPResp;

import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.ext.MessageBodyWriter;
import javax.ws.rs.ext.Provider;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;

/**
 * Handles writing {@link OCSPResp} objects
 *
 * @author wdawson
 */
@Provider
@Produces("application/ocsp-response")
public class OCSPRespMessageBodyWriter implements MessageBodyWriter<OCSPResp> {

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isWriteable(Class<?> type,
                               Type genericType,
                               Annotation[] annotations,
                               MediaType mediaType) {
        return type == OCSPResp.class;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public long getSize(OCSPResp ocspResp,
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
    public void writeTo(OCSPResp ocspResp,
                        Class<?> type,
                        Type genericType,
                        Annotation[] annotations,
                        MediaType mediaType,
                        MultivaluedMap<String, Object> httpHeaders,
                        OutputStream entityStream) throws IOException, WebApplicationException {
        byte[] encodedBytes = ocspResp.getEncoded();
        entityStream.write(encodedBytes);
    }
}
