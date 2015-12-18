package wdawson.samples.revoker.parsers.ocsp;

import java.io.IOException;
import java.io.InputStream;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.Consumes;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.NoContentException;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.MessageBodyReader;
import javax.ws.rs.ext.Provider;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;

/**
 * Handles reading {@link OCSPReq} objects
 *
 * @author wdawson
 */
@Provider
@Consumes("application/ocsp-request")
public class OCSPReqMessageBodyReader implements MessageBodyReader<OCSPReq> {

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isReadable(Class<?> aClass,
                              Type type,
                              Annotation[] annotations,
                              MediaType mediaType) {
        return type == OCSPReq.class;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public OCSPReq readFrom(Class<OCSPReq> aClass,
                            Type type,
                            Annotation[] annotations,
                            MediaType mediaType,
                            MultivaluedMap<String, String> multivaluedMap,
                            InputStream inputStream) throws IOException, WebApplicationException {
        ASN1Encodable asn1Encodable;
        try {
            asn1Encodable = new ASN1StreamParser(inputStream).readObject();
        } catch (IOException e) {
            throw new BadRequestException("Could not parse ASN1 OCSP request",
                    getOCSPErrorResponse(Response.Status.BAD_REQUEST, OCSPRespBuilder.MALFORMED_REQUEST),
                    e
            );
        }
        if (asn1Encodable == null) {
            throw new BadRequestException("Found no content for OCSP request",
                    getOCSPErrorResponse(Response.Status.BAD_REQUEST, OCSPRespBuilder.MALFORMED_REQUEST),
                    new NoContentException("Found no content for OCSP request")
            );
        }

        byte[] reqBytes = asn1Encodable.toASN1Primitive().getEncoded();
        try {
            return new OCSPReq(reqBytes);
        } catch (IOException e) {
            throw new BadRequestException("Could not parse OCSP request",
                    getOCSPErrorResponse(Response.Status.BAD_REQUEST, OCSPRespBuilder.MALFORMED_REQUEST),
                    e
            );
        }
    }

    private Response getOCSPErrorResponse(Response.Status httpStatusCode, int ocspErrorCode) {
        try {
            return Response.status(httpStatusCode).entity( new OCSPRespBuilder().build(ocspErrorCode, null)).build();
        } catch (OCSPException e) {
            throw new InternalServerErrorException("Could not return valid OCSP response", e);
        }
    }
}
