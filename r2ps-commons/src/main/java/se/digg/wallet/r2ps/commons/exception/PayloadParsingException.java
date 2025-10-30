package se.digg.wallet.r2ps.commons.exception;

import java.io.Serial;

public class PayloadParsingException extends Exception {
  @Serial private static final long serialVersionUID = -2931291609640952886L;

  public PayloadParsingException(final String message) {
    super(message);
  }

  public PayloadParsingException(final String message, final Throwable cause) {
    super(message, cause);
  }
}
