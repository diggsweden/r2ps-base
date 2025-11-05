package se.digg.wallet.r2ps.client.api.impl.strategy;

import static se.digg.wallet.r2ps.commons.dto.PakeProtocol.opaque;
import static se.digg.wallet.r2ps.commons.dto.PakeState.finalize;
import static se.digg.wallet.r2ps.commons.dto.servicetype.ServiceType.PIN_CHANGE;

import se.digg.wallet.r2ps.commons.dto.ServiceRequest;
import se.digg.wallet.r2ps.commons.dto.payload.PakeRequestPayload;

public class PinChangeStrategy implements PakeOperationStrategy {
  private final String pakeSessionId;

  public PinChangeStrategy(String pakeSessionId) {
    this.pakeSessionId = pakeSessionId;
  }

  @Override
  public PakeRequestPayload createFinalizePayload(byte[] requestData) {
    return PakeRequestPayload.builder()
        .protocol(opaque)
        .state(finalize)
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
        .serviceType(PIN_CHANGE)
        .nonce(nonce)
        .pakeSessionId(pakeSessionId)
        .build();
  }

  @Override
  public String getServiceTypeId() {
    return PIN_CHANGE;
  }
}
