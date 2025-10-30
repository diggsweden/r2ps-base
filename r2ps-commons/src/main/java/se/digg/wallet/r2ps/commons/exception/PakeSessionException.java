package se.digg.wallet.r2ps.commons.exception;

import java.io.Serial;

public class PakeSessionException extends Exception {

  @Serial private static final long serialVersionUID = 8081211478518234186L;

  public PakeSessionException(final String message) {
    super(message);
  }

  public PakeSessionException(final String message, final Throwable cause) {
    super(message, cause);
  }
}
