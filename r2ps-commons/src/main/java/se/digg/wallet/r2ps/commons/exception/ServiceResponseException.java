package se.digg.wallet.r2ps.commons.exception;

import java.io.Serial;

public class ServiceResponseException extends Exception {
  @Serial private static final long serialVersionUID = 8294745790481024051L;

  public ServiceResponseException(final String message) {
    super(message);
  }

  public ServiceResponseException(final String message, final Throwable cause) {
    super(message, cause);
  }
}
