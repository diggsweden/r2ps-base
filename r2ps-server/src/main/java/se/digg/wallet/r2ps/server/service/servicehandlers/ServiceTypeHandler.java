package se.digg.wallet.r2ps.server.service.servicehandlers;

import se.digg.wallet.r2ps.commons.dto.ServiceRequest;
import se.digg.wallet.r2ps.commons.dto.payload.ExchangePayload;
import se.digg.wallet.r2ps.commons.dto.servicetype.ServiceType;
import se.digg.wallet.r2ps.commons.exception.ServiceRequestHandlingException;
import se.digg.wallet.r2ps.server.pake.opaque.ServerPakeRecord;
import se.digg.wallet.r2ps.server.service.ClientPublicKeyRecord;

public interface ServiceTypeHandler {

  boolean supports(final ServiceType serviceType, final String context);

  ExchangePayload<?> processServiceRequest(
      ServiceRequest serviceRequest,
      ServerPakeRecord pakeSession,
      byte[] decryptedPayload,
      ClientPublicKeyRecord clientPublicKeyRecord,
      ServiceType serviceType)
      throws ServiceRequestHandlingException;
}
