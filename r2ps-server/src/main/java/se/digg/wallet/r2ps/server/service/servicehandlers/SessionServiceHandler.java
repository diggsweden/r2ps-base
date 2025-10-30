package se.digg.wallet.r2ps.server.service.servicehandlers;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import se.digg.wallet.r2ps.commons.dto.ErrorCode;
import se.digg.wallet.r2ps.commons.dto.ServiceRequest;
import se.digg.wallet.r2ps.commons.dto.payload.ExchangePayload;
import se.digg.wallet.r2ps.commons.dto.payload.StringPayload;
import se.digg.wallet.r2ps.commons.dto.servicetype.ServiceType;
import se.digg.wallet.r2ps.commons.exception.ServiceRequestHandlingException;
import se.digg.wallet.r2ps.commons.pake.opaque.PakeSessionRegistry;
import se.digg.wallet.r2ps.server.pake.opaque.ServerPakeRecord;
import se.digg.wallet.r2ps.server.service.ClientPublicKeyRecord;

@Slf4j
public class SessionServiceHandler implements ServiceTypeHandler {

  private final PakeSessionRegistry<ServerPakeRecord> serverPakeSessionRegistry;

  public SessionServiceHandler(PakeSessionRegistry<ServerPakeRecord> serverPakeSessionRegistry) {
    this.serverPakeSessionRegistry = serverPakeSessionRegistry;
  }

  @Override
  public boolean supports(final ServiceType serviceType, final String context) {
    return List.of(ServiceType.SESSION_END, ServiceType.SESSION_CONTEXT_END)
        .contains(serviceType.id());
  }

  @Override
  public ExchangePayload<?> processServiceRequest(
      final ServiceRequest serviceRequest,
      final ServerPakeRecord pakeSession,
      final byte[] decryptedPayload,
      final ClientPublicKeyRecord clientPublicKeyRecord,
      final ServiceType serviceType)
      throws ServiceRequestHandlingException {

    try {
      log.debug(
          "Handling session request {} for context {}",
          serviceType.id(),
          serviceRequest.getContext());
      final String context =
          Optional.ofNullable(serviceRequest.getContext())
              .orElseThrow(
                  () ->
                      new ServiceRequestHandlingException(
                          "No context in request", ErrorCode.ILLEGAL_REQUEST_DATA));
      final String clientId =
          Optional.ofNullable(serviceRequest.getClientID())
              .orElseThrow(
                  () ->
                      new ServiceRequestHandlingException(
                          "No client ID in request", ErrorCode.ILLEGAL_REQUEST_DATA));
      return switch (serviceType.id()) {
        case ServiceType.SESSION_END -> endSession(decryptedPayload);
        case ServiceType.SESSION_CONTEXT_END -> endContextSessions(
            clientId, serviceRequest.getKid(), context);
        default -> throw new ServiceRequestHandlingException(
            String.format("Unsupported service type %s", serviceType.id()),
            ErrorCode.ILLEGAL_REQUEST_DATA);
      };
    } catch (NullPointerException | IOException e) {
      throw new ServiceRequestHandlingException(
          String.format("Unable to process session request - %s", e.getMessage()),
          ErrorCode.SERVER_ERROR);
    }
  }

  private ExchangePayload<?> endSession(final byte[] decryptedPayload) throws IOException {
    String pakeSessionId = new StringPayload().deserialize(decryptedPayload).getStringValue();
    serverPakeSessionRegistry.deletePakeSession(pakeSessionId);
    return new StringPayload("OK");
  }

  private ExchangePayload<?> endContextSessions(
      final String clientId, final String kid, final String context) {
    final List<ServerPakeRecord> pakeSessions =
        serverPakeSessionRegistry.getPakeSessions(clientId, kid, context);
    for (ServerPakeRecord pakeSession : pakeSessions) {
      serverPakeSessionRegistry.deletePakeSession(pakeSession.getPakeSessionId());
    }
    return new StringPayload("OK");
  }
}
