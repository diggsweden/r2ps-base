package se.digg.wallet.r2ps.commons.exception;

import java.io.Serial;

public class PakeAuthenticationException extends Exception {
  @Serial
  private static final long serialVersionUID = 4148231016924946163L;

  public PakeAuthenticationException(final String message) {
    super(message);
  }

  public PakeAuthenticationException(final String message, final Throwable cause) {
    super(message, cause);
  }
}
