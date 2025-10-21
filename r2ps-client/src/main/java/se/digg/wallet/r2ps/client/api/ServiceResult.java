package se.digg.wallet.r2ps.client.api;

import se.digg.wallet.r2ps.commons.dto.ErrorResponse;
import se.digg.wallet.r2ps.commons.dto.ServiceResponse;
import se.digg.wallet.r2ps.commons.dto.payload.ExchangePayload;
import se.digg.wallet.r2ps.commons.exception.PayloadParsingException;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;

public record ServiceResult(
    ServiceResponse serviceResponse,
    byte[] decryptedPayload,
    ErrorResponse errorResponse,
    boolean success,
    int httpStatusCode
) {

  public <T extends ExchangePayload<T>> T getPayload(Class<T> payloadClass)
      throws PayloadParsingException {
    try {
      return payloadClass.getDeclaredConstructor().newInstance().deserialize(decryptedPayload);
    } catch (InvocationTargetException | InstantiationException | IllegalAccessException |
        NoSuchMethodException e) {
      throw new PayloadParsingException(
          String.format("Payload class %s has no suitable empty constructor - %s",
              payloadClass.getSimpleName(),
              e.getMessage()), e);
    } catch (IOException e) {
      throw new PayloadParsingException("Unable to parse the payload bytes to the specified type",
          e);
    }
  }

}
