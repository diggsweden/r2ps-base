package se.digg.wallet.r2ps.commons.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum ErrorCode {
  ILLEGAL_REQUEST_DATA(400),
  UNAUTHORIZED(401),
  ACCESS_DENIED(403),
  ILLEGAL_STATE(409),
  UNSUPPORTED_REQUEST_TYPE(415),
  IM_A_TEA_POT(418),
  SERVER_ERROR(500),
  SERVICE_UNAVAILABLE(503);

  private final int responseCode;
}
