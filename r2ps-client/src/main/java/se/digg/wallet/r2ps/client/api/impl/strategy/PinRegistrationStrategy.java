package se.digg.wallet.r2ps.client.api.impl.strategy;

import static se.digg.wallet.r2ps.commons.dto.PakeProtocol.opaque;
import static se.digg.wallet.r2ps.commons.dto.PakeState.finalize;
import static se.digg.wallet.r2ps.commons.dto.servicetype.ServiceType.PIN_REGISTRATION;

import se.digg.wallet.r2ps.commons.dto.ServiceRequest;
import se.digg.wallet.r2ps.commons.dto.payload.PakeRequestPayload;

public class PinRegistrationStrategy implements PakeOperationStrategy {
  private final byte[] authorization;

  public PinRegistrationStrategy(byte[] authorization) {
    this.authorization = authorization;
  }

  @Override
  public PakeRequestPayload createFinalizePayload(byte[] requestData) {

    return PakeRequestPayload.builder()
        .protocol(opaque)
        .state(finalize)
        .requestData(requestData)
        .authorization(authorization)
        .build();
  }

  @Override
  public ServiceRequest createServiceRequest(
      String clientId, String kid, String context, String nonce) {
    return ServiceRequest.builder()
        .clientID(clientId)
        .kid(kid)
        .context(context)
        .serviceType(PIN_REGISTRATION)
        .nonce(nonce)
        .build();
  }

  @Override
  public String getServiceTypeId() {
    return PIN_REGISTRATION;
  }
}
