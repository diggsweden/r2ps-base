package se.digg.wallet.r2ps.server.service.servicehandlers;

import static se.digg.wallet.r2ps.commons.dto.PakeState.finalize;

import java.io.IOException;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import lombok.Setter;
import se.digg.crypto.opaque.crypto.OprfPrivateKey;
import se.digg.crypto.opaque.dto.RegistrationResponse;
import se.digg.crypto.opaque.error.ClientAuthenticationException;
import se.digg.crypto.opaque.error.DeriveKeyPairErrorException;
import se.digg.crypto.opaque.error.DeserializationException;
import se.digg.crypto.opaque.error.InvalidInputException;
import se.digg.wallet.r2ps.commons.StaticResources;
import se.digg.wallet.r2ps.commons.dto.ErrorCode;
import se.digg.wallet.r2ps.commons.dto.PakeState;
import se.digg.wallet.r2ps.commons.dto.ServiceRequest;
import se.digg.wallet.r2ps.commons.dto.payload.ExchangePayload;
import se.digg.wallet.r2ps.commons.dto.payload.PakeRequestPayload;
import se.digg.wallet.r2ps.commons.dto.payload.PakeResponsePayload;
import se.digg.wallet.r2ps.commons.dto.servicetype.ServiceType;
import se.digg.wallet.r2ps.commons.dto.servicetype.SessionTaskRegistry;
import se.digg.wallet.r2ps.commons.exception.PakeSessionException;
import se.digg.wallet.r2ps.commons.exception.ServiceRequestHandlingException;
import se.digg.wallet.r2ps.commons.pake.ECUtils;
import se.digg.wallet.r2ps.commons.pake.opaque.OpaqueConfiguration;
import se.digg.wallet.r2ps.commons.pake.opaque.PakeSessionRegistry;
import se.digg.wallet.r2ps.server.pake.opaque.ClientRecordRegistry;
import se.digg.wallet.r2ps.server.pake.opaque.EvaluationResponseResult;
import se.digg.wallet.r2ps.server.pake.opaque.FinalizeResponse;
import se.digg.wallet.r2ps.server.pake.opaque.ServerOpaqueEntity;
import se.digg.wallet.r2ps.server.pake.opaque.ServerOpaqueProvider;
import se.digg.wallet.r2ps.server.pake.opaque.ServerPakeRecord;
import se.digg.wallet.r2ps.server.service.ClientPublicKeyRecord;
import se.digg.wallet.r2ps.server.service.pinauthz.PinAuthorization;

public class OpaqueServiceHandler implements ServiceTypeHandler {

  protected final List<String> supportedContexts;
  private final ServerOpaqueProvider opaqueProvider;
  private final PinAuthorization pinAuthorization;

  @Setter
  private Duration pinChangeMaxSessionAge = Duration.ofSeconds(30);

  public OpaqueServiceHandler(
      final List<String> supportedContexts,
      final PinAuthorization pinAuthorization,
      final ServerOpaqueProvider opaqueProvider) {
    this.supportedContexts = supportedContexts;
    this.opaqueProvider = opaqueProvider;
    this.pinAuthorization = pinAuthorization;
  }

  public OpaqueServiceHandler(
      final List<String> supportedContexts,
      final PinAuthorization pinAuthorization,
      OpaqueConfiguration opaqueConfiguration,
      String serverIdentity,
      byte[] oprfSeed,
      KeyPair serverOpaqueKeyPair,
      PakeSessionRegistry<ServerPakeRecord> pakeSessionRegistry,
      ClientRecordRegistry clientRecordRegistry,
      final SessionTaskRegistry sessionTaskRegistry,
      Duration maxSessionDuration,
      Duration finalizeDuration) {
    this.pinAuthorization = pinAuthorization;
    this.supportedContexts = supportedContexts;
    ServerOpaqueEntity serverOpaqueEntity =
        ServerOpaqueEntity.builder()
            .opaqueServer(opaqueConfiguration.getOpaqueServer())
            .serverIdentity(serverIdentity)
            .oprfSeed(oprfSeed)
            .serverOpaquePrivateKey(new OprfPrivateKey(serverOpaqueKeyPair))
            .serverOpaquePublicKey(ECUtils.serializePublicKey(serverOpaqueKeyPair.getPublic()))
            .build();
    opaqueProvider =
        new ServerOpaqueProvider(
            serverOpaqueEntity,
            pakeSessionRegistry,
            clientRecordRegistry,
            sessionTaskRegistry,
            maxSessionDuration,
            finalizeDuration);
  }

  @Override
  public boolean supports(final ServiceType serviceType, final String context) {
    return List.of(ServiceType.AUTHENTICATE, ServiceType.PIN_CHANGE, ServiceType.PIN_REGISTRATION)
        .contains(serviceType.id())
        && this.supportedContexts.contains(context);
  }

  @Override
  public ExchangePayload<?> processServiceRequest(
      final ServiceRequest serviceRequest,
      final ServerPakeRecord pakeSession,
      final byte[] decryptedPayload,
      final ClientPublicKeyRecord clientPublicKeyRecord,
      final ServiceType serviceType)
      throws ServiceRequestHandlingException {
    switch (serviceType.id()) {
      case ServiceType.AUTHENTICATE -> {
        return processOpaqueAuthentication(serviceRequest, decryptedPayload);
      }
      case ServiceType.PIN_CHANGE, ServiceType.PIN_REGISTRATION -> {
        return processOpaquePinRegistration(
            serviceRequest, pakeSession, decryptedPayload, clientPublicKeyRecord, serviceType);
      }
      default ->
        throw new ServiceRequestHandlingException(
            "Unsupported service type: " + serviceType.id(), ErrorCode.ILLEGAL_REQUEST_DATA);
    }
  }

  private ExchangePayload<?> processOpaquePinRegistration(
      final ServiceRequest serviceRequest,
      final ServerPakeRecord pakeSession,
      final byte[] decryptedPayload,
      final ClientPublicKeyRecord clientPublicKeyRecord,
      final ServiceType serviceType)
      throws ServiceRequestHandlingException {

    try {
      final PakeRequestPayload pakeRequestPayload =
          StaticResources.TIME_STAMP_SECONDS_MAPPER.readValue(
              decryptedPayload, PakeRequestPayload.class);
      // Check authorization if the pake state the "finalize" state.
      if (serviceType.id().equals(ServiceType.PIN_REGISTRATION)
          && pakeRequestPayload.getState().equals(finalize)) {

        boolean match =
            pinAuthorization.authorize(
                pakeRequestPayload.getAuthorization(),
                clientPublicKeyRecord.getKid(),
                serviceRequest.getClientID());
        pinAuthorization.clearAuthorization(
            serviceRequest.getClientID(), clientPublicKeyRecord.getKid());
        if (!match) {
          throw new ServiceRequestHandlingException(
              "Provided authorization code is invalid", ErrorCode.ACCESS_DENIED);
        }
      }
      if (serviceType.id().equals(ServiceType.PIN_CHANGE)
          && Instant.now().isAfter(pakeSession.getCreationTime().plus(pinChangeMaxSessionAge))) {
        throw new ServiceRequestHandlingException(
            "Session is too old for a PIN change request", ErrorCode.ACCESS_DENIED);
      }

      final PakeState state = pakeRequestPayload.getState();
      if (state == null) {
        throw new ServiceRequestHandlingException(
            "PAKE request payload has no pake state", ErrorCode.ILLEGAL_REQUEST_DATA);
      }

      // Create the response payload
      return switch (state) {
        case evaluate -> {
          final RegistrationResponse registrationResponse =
              opaqueProvider.registrationResponse(
                  pakeRequestPayload.getRequestData(), serviceRequest.getKid());
          yield PakeResponsePayload.builder()
              .responseData(registrationResponse.getEncoded())
              .build();
        }
        case finalize -> {
          opaqueProvider.registrationFinalize(
              serviceRequest.getClientID(),
              serviceRequest.getKid(),
              pakeRequestPayload.getRequestData());
          yield PakeResponsePayload.builder().message("OK").build();
        }
      };
    } catch (IOException | DeriveKeyPairErrorException | DeserializationException e) {
      throw new ServiceRequestHandlingException(
          "Error processing PIN registration request: " + e.getMessage(),
          e,
          ErrorCode.ILLEGAL_REQUEST_DATA);
    }
  }

  /**
   * Processes authentication requests using the OPAQUE protocol. Depending on the state of the PAKE
   * (Password Authenticated Key Exchange) request (EVALUATE or FINALIZE), this method evaluates or
   * finalizes the authentication process and creates an appropriate response payload.
   *
   * @param serviceRequest the request object containing client information, key identifiers, and
   *        other contextual data needed to process the PAKE request
   * @param decryptedPayload the decrypted payload of the request, expected to contain PAKE-specific
   *        data for processing authentication
   * @return an {@code ExchangePayload<?>} containing the processed response data based on the PAKE
   *         state, which may include evaluation results or finalization details
   * @throws ServiceRequestHandlingException if an error occurs during the handling of the
   *         authentication request, such as missing or invalid input data, decryption issues, or
   *         other protocol-specific exceptions
   */
  private ExchangePayload<?> processOpaqueAuthentication(
      final ServiceRequest serviceRequest, final byte[] decryptedPayload)
      throws ServiceRequestHandlingException {

    try {
      final PakeRequestPayload pakeRequestPayload =
          StaticResources.TIME_STAMP_SECONDS_MAPPER.readValue(
              decryptedPayload, PakeRequestPayload.class);

      final PakeState state = pakeRequestPayload.getState();
      if (state == null) {
        throw new ServiceRequestHandlingException(
            "PAKE request payload has no pake state", ErrorCode.ILLEGAL_REQUEST_DATA);
      }

      // Create the response payload
      return switch (state) {
        case evaluate -> {
          final EvaluationResponseResult evaluationResult =
              opaqueProvider.evaluateAuthRequest(
                  pakeRequestPayload.getRequestData(),
                  serviceRequest.getClientID(),
                  serviceRequest.getKid(),
                  serviceRequest.getContext());
          yield PakeResponsePayload.builder()
              .responseData(evaluationResult.ke2().getEncoded())
              .pakeSessionId(evaluationResult.pakeSessionId())
              .build();
        }
        case finalize -> {
          FinalizeResponse finalizeResponse =
              opaqueProvider.finalizeAuthRequest(
                  pakeRequestPayload.getRequestData(),
                  serviceRequest.getPakeSessionId(),
                  pakeRequestPayload.getTask(),
                  pakeRequestPayload.getSessionDuration());
          yield PakeResponsePayload.builder()
              .pakeSessionId(finalizeResponse.pakeSessionId())
              .task(finalizeResponse.sessionTask())
              .sessionExpirationTime(finalizeResponse.sessionExpirationTime())
              .message("OK")
              .build();
        }
      };

    } catch (IOException
        | InvalidInputException
        | DeriveKeyPairErrorException
        | DeserializationException
        | ClientAuthenticationException
        | PakeSessionException e) {
      throw new ServiceRequestHandlingException(
          "Failed to process authentication request: " + e.getMessage(),
          e,
          ErrorCode.ILLEGAL_REQUEST_DATA);
    }
  }
}
