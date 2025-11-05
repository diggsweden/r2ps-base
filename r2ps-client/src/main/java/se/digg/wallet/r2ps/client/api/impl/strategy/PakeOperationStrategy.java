package se.digg.wallet.r2ps.client.api.impl.strategy;

import se.digg.wallet.r2ps.commons.dto.ServiceRequest;
import se.digg.wallet.r2ps.commons.dto.payload.PakeRequestPayload;

public interface PakeOperationStrategy {
  PakeRequestPayload createFinalizePayload(byte[] requestData);

  ServiceRequest createServiceRequest(String clientId, String kid, String context, String nonce);

  String getServiceTypeId();
}
