package wdawson.samples.revoker.parsers.ocsp;

import java.io.IOException;
import java.io.InputStream;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;
import javax.ws.rs.Consumes;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.ext.MessageBodyReader;
import javax.ws.rs.ext.Provider;
import org.bouncycastle.cert.ocsp.OCSPResp;

/**
 * Handles reading {@link OCSPResp} objects
 *
 * @author wdawson
 */
@Provider
@Consumes("application/ocsp-response")
public class OCSPRespMessageBodyReader implements MessageBodyReader<OCSPResp> {

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isReadable(Class<?> type, Type genericType,
                              Annotation[] annotations,
                              MediaType mediaType) {
        return type == OCSPResp.class;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public OCSPResp readFrom(Class<OCSPResp> type,
                             Type genericType,
                             Annotation[] annotations,
                             MediaType mediaType,
                             MultivaluedMap<String, String> httpHeaders,
                             InputStream entityStream) throws IOException, WebApplicationException {
        return new OCSPResp(entityStream);
    }
}
