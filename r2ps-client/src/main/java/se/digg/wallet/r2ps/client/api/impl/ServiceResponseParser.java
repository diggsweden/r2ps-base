package se.digg.wallet.r2ps.client.api.impl;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import java.io.IOException;
import java.text.ParseException;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.digg.wallet.r2ps.client.api.ServiceResult;
import se.digg.wallet.r2ps.commons.StaticResources;
import se.digg.wallet.r2ps.commons.dto.ErrorResponse;
import se.digg.wallet.r2ps.commons.dto.HttpResponse;
import se.digg.wallet.r2ps.commons.dto.ServiceResponse;
import se.digg.wallet.r2ps.commons.exception.ServiceResponseException;
import se.digg.wallet.r2ps.commons.jwe.JweDecryptor;
import se.digg.wallet.r2ps.commons.utils.Utils;

public class ServiceResponseParser {

  private static final Logger log = LoggerFactory.getLogger(ServiceResponseParser.class);

  private ServiceResponseParser() {
    // Static utility class
  }

  public static ServiceResult parse(
      final HttpResponse httpResponse, JweDecryptor jweDecryptor, JWSVerifier jwsVerifier)
      throws ServiceResponseException {

    if (httpResponse == null || httpResponse.responseData() == null) {
      throw new ServiceResponseException("No service response data from server");
    }

    try {
      if (httpResponse.responseCode() == 200) {
        return parseSuccessResponse(httpResponse, jweDecryptor, jwsVerifier);
      } else {
        return parseErrorResponse(httpResponse);
      }
    } catch (IOException | ParseException | JOSEException e) {
      throw new ServiceResponseException("Failed to parse service response", e);
    }
  }

  private static ServiceResult parseSuccessResponse(
      final HttpResponse httpResponse, JweDecryptor jweDecryptor, JWSVerifier jwsVerifier)
      throws ParseException, JOSEException, IOException, ServiceResponseException {

    final String responseData = httpResponse.responseData();
    JWSObject jwsObject = JWSObject.parse(responseData);

    verifySignature(jwsVerifier, jwsObject);

    ServiceResponse serviceResponse =
        StaticResources.TIME_STAMP_SECONDS_MAPPER.convertValue(
            jwsObject.getPayload().toJSONObject(), ServiceResponse.class);

    validateTimestamp(serviceResponse);

    final byte[] serviceData = serviceResponse.getServiceData();
    byte[] decryptedPayload = jweDecryptor.decrypt(serviceData);

    if (log.isDebugEnabled()) {
      log.debug(
          "Client received service response with valid signature:\n{}",
          StaticResources.TIME_STAMP_SECONDS_MAPPER
              .writerWithDefaultPrettyPrinter()
              .writeValueAsString(serviceResponse));

      log.debug(
          "Service data in service response:\n{}", Utils.prettyPrintByteArray(decryptedPayload));
    }
    return new ServiceResult(
        serviceResponse, decryptedPayload, null, true, httpResponse.responseCode());
  }

  private static ServiceResult parseErrorResponse(final HttpResponse httpResponse)
      throws IOException {
    final String responseData = httpResponse.responseData();
    final int responseCode = httpResponse.responseCode();

    ErrorResponse errorResponse =
        StaticResources.TIME_STAMP_SECONDS_MAPPER.readValue(responseData, ErrorResponse.class);

    if (log.isDebugEnabled()) {
      log.debug(
          "Received error response with http status code: {}\n{}",
          responseCode,
          StaticResources.TIME_STAMP_SECONDS_MAPPER
              .writerWithDefaultPrettyPrinter()
              .writeValueAsString(errorResponse));
    }
    return new ServiceResult(null, null, errorResponse, false, responseCode);
  }

  private static void validateTimestamp(ServiceResponse serviceResponse)
      throws ServiceResponseException {
    if (Instant.now().isAfter(serviceResponse.getIat().plusSeconds(30))) {
      throw new ServiceResponseException("Service response is more than 30 seconds old");
    }
  }

  private static void verifySignature(JWSVerifier jwsVerifier, JWSObject jwsObject)
      throws JOSEException, ServiceResponseException {
    if (!jwsObject.verify(jwsVerifier)) {
      throw new ServiceResponseException("Failed to verify service response signature");
    }
  }
}
