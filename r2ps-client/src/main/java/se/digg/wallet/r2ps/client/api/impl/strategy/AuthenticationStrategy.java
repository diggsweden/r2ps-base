package se.digg.wallet.r2ps.client.api.impl.strategy;

import static se.digg.wallet.r2ps.commons.dto.PakeProtocol.opaque;
import static se.digg.wallet.r2ps.commons.dto.PakeState.finalize;
import static se.digg.wallet.r2ps.commons.dto.servicetype.ServiceType.AUTHENTICATE;

import java.time.Duration;
import se.digg.wallet.r2ps.commons.dto.ServiceRequest;
import se.digg.wallet.r2ps.commons.dto.payload.PakeRequestPayload;

public class AuthenticationStrategy implements PakeOperationStrategy {

  private final String pakeSessionId;
  private final String task;
  private final Duration sessionDuration;

  public AuthenticationStrategy(String pakeSessionId, String task, Duration sessionDuration) {
    this.pakeSessionId = pakeSessionId;
    this.task = task;
    this.sessionDuration = sessionDuration;
  }

  @Override
  public PakeRequestPayload createFinalizePayload(byte[] requestData) {
    return PakeRequestPayload.builder()
        .protocol(opaque)
        .state(finalize)
        .sessionDuration(sessionDuration)
        .task(task)
        .requestData(requestData)
        .build();
  }

  @Override
  public ServiceRequest createServiceRequest(
      String clientId, String kid, String context, String nonce) {
    return ServiceRequest.builder()
        .clientID(clientId)
        .kid(kid)
        .context(context)
        .serviceType(AUTHENTICATE)
        .nonce(nonce)
        .pakeSessionId(pakeSessionId)
        .build();
  }

  @Override
  public String getServiceTypeId() {
    return AUTHENTICATE;
  }
}
