package se.digg.wallet.r2ps.it.testimpl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSObject;
import lombok.extern.slf4j.Slf4j;
import se.digg.wallet.r2ps.client.api.ServiceExchangeConnector;
import se.digg.wallet.r2ps.commons.StaticResources;
import se.digg.wallet.r2ps.commons.dto.ErrorCode;
import se.digg.wallet.r2ps.commons.dto.ErrorResponse;
import se.digg.wallet.r2ps.commons.dto.HttpResponse;
import se.digg.wallet.r2ps.commons.exception.ServiceRequestHandlingException;
import se.digg.wallet.r2ps.server.service.ServiceRequestHandler;

import java.text.ParseException;

@Slf4j
public class TestConnector implements ServiceExchangeConnector {

  private static final ObjectMapper objectMapper = StaticResources.SERVICE_EXCHANGE_OBJECT_MAPPER;

  private final ServiceRequestHandler serviceRequestHandler;

  public TestConnector(final ServiceRequestHandler serviceRequestHandler) {
    this.serviceRequestHandler = serviceRequestHandler;
  }

  @Override
  public HttpResponse requestService(final String serviceRequest) {

    try {
      if (log.isDebugEnabled()) {
        logServiceRequest(serviceRequest);
      }
      final String serviceResponse = serviceRequestHandler.handleServiceRequest(serviceRequest);
      if (log.isDebugEnabled()) {
        logServiceResponse(serviceResponse);
      }
      return new HttpResponse(serviceResponse, 200);
    } catch (ServiceRequestHandlingException e) {
      return getErrorResponseString(e.getErrorCode(), e.getMessage());
    }
  }

  private void logServiceResponse(final String serviceResponse) {
    log.trace("Service response JWS: {}", serviceResponse);
    try {
      JWSObject jwsObject = JWSObject.parse(serviceResponse);
      log.trace("Received Service response:\n{}", objectMapper.writeValueAsString(
          jwsObject.getPayload().toJSONObject()
      ));
    } catch (JsonProcessingException | ParseException e) {
      throw new RuntimeException(e);
    }
  }

  private void logServiceRequest(final String serviceRequest) {
    log.trace("Service request JWS: {}", serviceRequest);
    try {
      JWSObject jwsObject = JWSObject.parse(serviceRequest);
      log.trace("Sending service request:\n{}", objectMapper.writeValueAsString(
          jwsObject.getPayload().toJSONObject()
      ));
    } catch (JsonProcessingException | ParseException e) {
      throw new RuntimeException(e);
    }
  }

  private HttpResponse getErrorResponseString(ErrorCode errorCode, String message) {
    try {
      return new HttpResponse(objectMapper.writeValueAsString(ErrorResponse.builder()
          .errorCode(errorCode.name())
          .message(message)
          .build()), errorCode.getResponseCode());
    } catch (JsonProcessingException e) {
      throw new RuntimeException(e);
    }
  }

}
