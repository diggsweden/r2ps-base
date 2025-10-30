package se.digg.wallet.r2ps.commons.exception;

import java.io.Serial;

public class ServiceRequestException extends Exception {
  @Serial private static final long serialVersionUID = 738529243418495043L;

  public ServiceRequestException(final String message) {
    super(message);
  }

  public ServiceRequestException(final String message, final Throwable cause) {
    super(message, cause);
  }
}
