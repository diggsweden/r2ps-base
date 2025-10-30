package se.digg.wallet.r2ps.client.api.impl;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import java.io.IOException;
import java.text.ParseException;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.digg.wallet.r2ps.client.api.ClientContextConfiguration;
import se.digg.wallet.r2ps.client.api.ServiceResult;
import se.digg.wallet.r2ps.commons.StaticResources;
import se.digg.wallet.r2ps.commons.dto.EncryptOption;
import se.digg.wallet.r2ps.commons.dto.ErrorResponse;
import se.digg.wallet.r2ps.commons.dto.HttpResponse;
import se.digg.wallet.r2ps.commons.dto.JWEEncryptionParams;
import se.digg.wallet.r2ps.commons.dto.ServiceResponse;
import se.digg.wallet.r2ps.commons.dto.servicetype.ServiceType;
import se.digg.wallet.r2ps.commons.dto.servicetype.ServiceTypeRegistry;
import se.digg.wallet.r2ps.commons.exception.ServiceResponseException;
import se.digg.wallet.r2ps.commons.utils.Utils;

public class ServiceResponseParser {

  private static final Logger log = LoggerFactory.getLogger(ServiceResponseParser.class);

  private ServiceResponseParser() {
    // Static utility class
  }

  public static ServiceResult parse(
      final HttpResponse httpResponse,
      JWEEncryptionParams encryptionParams,
      ClientContextConfiguration clientContextConfiguration,
      final String serviceTypeId,
      ServiceTypeRegistry serviceTypeRegistry)
      throws ServiceResponseException {
    if (httpResponse == null) {
      throw new ServiceResponseException("No service response from server");
    }
    final String responseData = httpResponse.responseData();
    if (responseData == null) {
      throw new ServiceResponseException("No service response data from server");
    }
    try {
      final int responseCode = httpResponse.responseCode();
      boolean success = responseCode == 200;
      ServiceResponse serviceResponse = null;
      ErrorResponse errorResponse = null;
      byte[] decryptedPayload = null;
      if (success) {
        JWSObject jwsObject = JWSObject.parse(responseData);
        if (!jwsObject.verify(clientContextConfiguration.getServerVerifier())) {
          throw new ServiceResponseException("Failed to verify service response signature");
        }
        jwsObject.getPayload().toJSONObject();
        serviceResponse =
            StaticResources.TIME_STAMP_SECONDS_MAPPER.convertValue(
                jwsObject.getPayload().toJSONObject(), ServiceResponse.class);
        if (Instant.now().isAfter(serviceResponse.getIat().plusSeconds(30))) {
          throw new ServiceResponseException("Service response is more than 30 seconds old");
        }
        final byte[] serviceData = serviceResponse.getServiceData();
        final ServiceType serviceType = serviceTypeRegistry.getServiceType(serviceTypeId);
        decryptedPayload = serviceData;
        if (EncryptOption.user == serviceType.encryptKey()) {
          decryptedPayload = Utils.decryptJWE(serviceData, encryptionParams);
        }
        if (EncryptOption.device == serviceType.encryptKey()) {
          decryptedPayload =
              Utils.decryptJWEECDH(serviceData, encryptionParams.staticPrivateRecipientKey());
        }
        if (log.isDebugEnabled()) {
          log.debug(
              "Client received service response with valid signature:\n{}",
              StaticResources.TIME_STAMP_SECONDS_MAPPER
                  .writerWithDefaultPrettyPrinter()
                  .writeValueAsString(serviceResponse));

          log.debug(
              "Service data in service response{}:\n{}",
              EncryptOption.user == serviceType.encryptKey() ? " after decryption" : "",
              Utils.prettyPrintByteArray(decryptedPayload));
        }
      } else {
        errorResponse =
            StaticResources.TIME_STAMP_SECONDS_MAPPER.readValue(responseData, ErrorResponse.class);
        if (log.isDebugEnabled()) {
          log.debug(
              "Received error response with http status code: {}\n{}",
              responseCode,
              StaticResources.TIME_STAMP_SECONDS_MAPPER
                  .writerWithDefaultPrettyPrinter()
                  .writeValueAsString(errorResponse));
        }
      }
      return new ServiceResult(
          serviceResponse, decryptedPayload, errorResponse, success, responseCode);
    } catch (IOException | ParseException | JOSEException e) {
      throw new ServiceResponseException("Failed to parse service response", e);
    }
  }
}
