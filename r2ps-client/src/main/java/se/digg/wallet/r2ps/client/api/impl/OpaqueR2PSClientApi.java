package se.digg.wallet.r2ps.client.api.impl;

import static se.digg.wallet.r2ps.commons.dto.PakeState.evaluate;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;
import se.digg.crypto.opaque.OpaqueUtils;
import se.digg.crypto.opaque.client.ClientKeyExchangeResult;
import se.digg.crypto.opaque.client.ClientState;
import se.digg.crypto.opaque.client.RegistrationRequestResult;
import se.digg.crypto.opaque.dto.KE1;
import se.digg.crypto.opaque.dto.KE3;
import se.digg.crypto.opaque.dto.RegistrationRecord;
import se.digg.wallet.r2ps.client.api.ClientContextConfiguration;
import se.digg.wallet.r2ps.client.api.R2PSClientApi;
import se.digg.wallet.r2ps.client.api.ServiceExchangeConnector;
import se.digg.wallet.r2ps.client.api.ServiceResult;
import se.digg.wallet.r2ps.client.api.impl.strategy.AuthenticationStrategy;
import se.digg.wallet.r2ps.client.api.impl.strategy.PakeOperationStrategy;
import se.digg.wallet.r2ps.client.api.impl.strategy.PinChangeStrategy;
import se.digg.wallet.r2ps.client.api.impl.strategy.PinRegistrationStrategy;
import se.digg.wallet.r2ps.client.jwe.JweCodecFactory;
import se.digg.wallet.r2ps.client.pake.PinHardening;
import se.digg.wallet.r2ps.client.pake.impl.ECPrivateKeyDHPinHardening;
import se.digg.wallet.r2ps.client.pake.opaque.ClientOpaqueProvider;
import se.digg.wallet.r2ps.client.pake.opaque.ClientPakeRecord;
import se.digg.wallet.r2ps.commons.StaticResources;
import se.digg.wallet.r2ps.commons.dto.EncryptOption;
import se.digg.wallet.r2ps.commons.dto.PakeProtocol;
import se.digg.wallet.r2ps.commons.dto.ServiceRequest;
import se.digg.wallet.r2ps.commons.dto.ServiceResponse;
import se.digg.wallet.r2ps.commons.dto.payload.ExchangePayload;
import se.digg.wallet.r2ps.commons.dto.payload.NullPayload;
import se.digg.wallet.r2ps.commons.dto.payload.PakeRequestPayload;
import se.digg.wallet.r2ps.commons.dto.payload.PakeResponsePayload;
import se.digg.wallet.r2ps.commons.dto.payload.StringPayload;
import se.digg.wallet.r2ps.commons.dto.servicetype.ServiceType;
import se.digg.wallet.r2ps.commons.dto.servicetype.ServiceTypeRegistry;
import se.digg.wallet.r2ps.commons.exception.PakeAuthenticationException;
import se.digg.wallet.r2ps.commons.exception.PakeSessionException;
import se.digg.wallet.r2ps.commons.exception.ServiceRequestException;
import se.digg.wallet.r2ps.commons.exception.ServiceResponseException;
import se.digg.wallet.r2ps.commons.jwe.JweCodec;
import se.digg.wallet.r2ps.commons.pake.opaque.PakeSessionRegistry;
import se.digg.wallet.r2ps.commons.utils.ServiceExchangeBuilder;

@Slf4j
public class OpaqueR2PSClientApi implements R2PSClientApi {

  private final String clientId;
  private final ClientOpaqueProvider opaqueProvider;
  private final ServiceExchangeConnector connector;
  private final ServiceTypeRegistry serviceTypeRegistry;
  private final JweCodecFactory jweCodecFactory;
  private final PakeSessionRegistry<ClientPakeRecord> sessionRegistry;

  /** A map keyed by context, holding info about that context */
  private final Map<String, ClientContextConfiguration> contextInfoMap;

  private final PinHardening pinHardening;

  @Setter
  private EncryptionMethod encryptionMethod = EncryptionMethod.A256GCM;

  public OpaqueR2PSClientApi(OpaqueR2PSConfiguration configuration) {
    this.clientId = configuration.getClientIdentity();
    this.opaqueProvider =
        new ClientOpaqueProvider(configuration.getOpaqueConfiguration().getOpaqueClient());
    this.sessionRegistry = configuration.getClientPakeSessionRegistry();
    this.connector = configuration.getServiceExchangeConnector();
    this.serviceTypeRegistry = configuration.getServiceTypeRegistry();
    this.contextInfoMap = configuration.getContextConfigurationMap();
    this.pinHardening =
        new ECPrivateKeyDHPinHardening(
            configuration.getOpaqueConfiguration().getHashToCurveProfile());
    this.jweCodecFactory = new JweCodecFactory(encryptionMethod);
  }

  @Override
  public PakeResponsePayload createSession(final String pin, final String context)
      throws PakeSessionException, ServiceResponseException, PakeAuthenticationException {
    return createSession(pin, context, null, null);
  }

  @Override
  public PakeResponsePayload createSession(
      final String pin, final String context, String task, Duration requestedDuration)
      throws PakeSessionException, ServiceResponseException, PakeAuthenticationException {
    log.debug("Creating session for context {}", context);

    final ClientContextConfiguration clientContextConfiguration = contextInfoMap.get(context);
    if (clientContextConfiguration == null) {
      throw new PakeSessionException(String.format("The context %s is not available", context));
    }

    JweCodec jweCodec = jweCodecFactory.forDeviceAuthentication(clientContextConfiguration);

    AuthenticationCredentialResponse evaluateResponse =
        initiateAuthentication(pin, clientContextConfiguration, context, jweCodec);
    String pakeSessionId = evaluateResponse.pakeSessionId();

    try {
      return completeAuthentication(
          evaluateResponse, context, clientContextConfiguration, jweCodec, task, requestedDuration);
    } catch (ServiceResponseException | PakeSessionException | PakeAuthenticationException e) {
      if (pakeSessionId != null) {
        sessionRegistry.deletePakeSession(pakeSessionId);
      }
      throw e;
    }
  }

  private AuthenticationCredentialResponse initiateAuthentication(
      String pin,
      ClientContextConfiguration clientContextConfiguration,
      String context,
      JweCodec jweCodec)
      throws PakeAuthenticationException, ServiceResponseException {

    final byte[] hPin = hardenPin(pin, clientContextConfiguration);
    ClientState clientState = new ClientState();
    final KE1 ke1 = opaqueProvider.authenticationEvaluate(hPin, clientState);

    PakeResponsePayload response =
        performPakeEvaluation(
            context,
            ServiceType.AUTHENTICATE,
            ke1.getEncoded(),
            null,
            clientContextConfiguration,
            jweCodec);

    return new AuthenticationCredentialResponse(
        response.getPakeSessionId(), response.getResponseData(), clientState);
  }

  private PakeResponsePayload completeAuthentication(
      AuthenticationCredentialResponse evaluateResponse,
      String context,
      ClientContextConfiguration clientContextConfiguration,
      JweCodec jweCodec,
      String task,
      Duration requestedDuration)
      throws PakeAuthenticationException, ServiceResponseException, PakeSessionException {

    byte[] ke2 = evaluateResponse.responseData();
    String pakeSessionId = evaluateResponse.pakeSessionId();

    ClientKeyExchangeResult clientKeyExchangeResult =
        opaqueProvider.authenticationFinalize(
            ke2,
            evaluateResponse.clientState(),
            clientContextConfiguration.getServerIdentity(),
            clientId);

    sessionRegistry.addPakeSession(
        ClientPakeRecord.builder()
            .clientId(clientId)
            .pakeSessionId(pakeSessionId)
            .kid(clientContextConfiguration.getKid())
            .context(context)
            .requestedSessionTaskId(task)
            .sessionKey(clientKeyExchangeResult.sessionKey())
            .exportKey(clientKeyExchangeResult.exportKey())
            .build());

    KE3 ke3 = clientKeyExchangeResult.ke3();

    PakeResponsePayload finalizeResponsePayload =
        performPakeFinalization(
            context,
            ke3.getEncoded(),
            clientContextConfiguration,
            jweCodec,
            new AuthenticationStrategy(pakeSessionId, task, requestedDuration));

    log.debug("Created session for context {} with sessionID {}", context, pakeSessionId);

    if (finalizeResponsePayload.getSessionExpirationTime() == null) {
      throw new PakeSessionException("No session expiration time from server. Abort session");
    }

    ClientPakeRecord pakeSession = sessionRegistry.getPakeSession(pakeSessionId);
    pakeSession.setExpirationTime(finalizeResponsePayload.getSessionExpirationTime());
    pakeSession.setSessionTaskId(finalizeResponsePayload.getTask());
    sessionRegistry.updatePakeSession(pakeSession);

    return finalizeResponsePayload;
  }

  @Override
  public void deleteContextSessions(final String context) throws PakeSessionException {
    if (!contextInfoMap.containsKey(context)) {
      log.debug("The context {} is not registered in the context registry.", context);
      throw new PakeSessionException(
          String.format(
              "Failed to delete context session for context " + "'%s' No such context", context));
    }
    final ClientContextConfiguration clientContextConfiguration = contextInfoMap.get(context);
    final List<ClientPakeRecord> pakeSession =
        sessionRegistry.getPakeSessions(clientId, clientContextConfiguration.getKid(), context);
    // Attempting to delete sessions from local registry
    if (!pakeSession.isEmpty()) {
      for (ClientPakeRecord clientPakeRecord : pakeSession) {
        log.debug(
            "Deleting session for context {} with session id {}",
            context,
            clientPakeRecord.getPakeSessionId());
        sessionRegistry.deletePakeSession(clientPakeRecord.getPakeSessionId());
      }
    } else {
      log.debug("No active session for context {}. Nothing to delete", context);
    }
    // Attempting to delete all context sessions from the server
    try {
      deviceAuthenticatedService(ServiceType.SESSION_CONTEXT_END, new NullPayload(), context);
    } catch (PakeAuthenticationException | ServiceResponseException | ServiceRequestException e) {
      log.warn(
          "Failed to interact with server to delete context sessions for context {}", context, e);
    }
  }

  @Override
  public void deleteSession(final String sessionId) throws PakeSessionException {
    log.debug("Deleting session with session id {}", sessionId);

    // fetching session because we need the context
    final ClientPakeRecord pakeSession = sessionRegistry.getPakeSession(sessionId);
    if (pakeSession == null) {
      log.debug("Session {} is not present", sessionId);
      return;
    }
    String context = pakeSession.getContext();

    sessionRegistry.deletePakeSession(sessionId);
    log.debug("Deleted session {} for context {} from local registry", sessionId, context);

    try {
      deviceAuthenticatedService(ServiceType.SESSION_END, new StringPayload(sessionId), context);
      log.debug("Deleted session {} for context {} from server", sessionId, context);
    } catch (PakeAuthenticationException | ServiceResponseException | ServiceRequestException e) {
      log.warn("Failed to interact with server to delete session {}", sessionId, e);
    }
  }

  @Override
  public void registerPin(final String pin, final String context, final byte[] authorization)
      throws PakeSessionException, PakeAuthenticationException, ServiceResponseException {

    if (authorization == null) {
      throw new PakeSessionException("A PIN registration request MUST contain an authorization");
    }

    final ClientContextConfiguration clientContextConfiguration = contextInfoMap.get(context);
    if (clientContextConfiguration == null) {
      throw new PakeSessionException(String.format("The context %s is not available", context));
    }

    JweCodec jweCodec = jweCodecFactory.forDeviceAuthentication(clientContextConfiguration);

    final byte[] hPin = hardenPin(pin, clientContextConfiguration);

    PinCredentialResponse pinCredentialResponse =
        initiateRegisterPin(hPin, clientContextConfiguration, context, jweCodec);

    completeRegisterPin(
        hPin, pinCredentialResponse, clientContextConfiguration, context, authorization, jweCodec);

    log.debug("PIN registration completed for context {}", context);
  }

  private PinCredentialResponse initiateRegisterPin(
      byte[] hardenedPin,
      ClientContextConfiguration clientContextConfiguration,
      String context,
      JweCodec jweCodec)
      throws PakeAuthenticationException, ServiceResponseException {

    final RegistrationRequestResult registrationRequestBundle =
        opaqueProvider.createRegistrationRequest(hardenedPin);

    PakeResponsePayload evaluateResponsePayload =
        performPakeEvaluation(
            context,
            ServiceType.PIN_REGISTRATION,
            registrationRequestBundle.registrationRequest().getEncoded(),
            null,
            clientContextConfiguration,
            jweCodec);

    return new PinCredentialResponse(
        evaluateResponsePayload.getResponseData(), registrationRequestBundle.blind());
  }

  private void completeRegisterPin(
      byte[] hardenedPin,
      PinCredentialResponse pinCredentialResponse,
      ClientContextConfiguration clientContextConfiguration,
      String context,
      byte[] authorization,
      JweCodec jweCodec)
      throws PakeAuthenticationException, ServiceResponseException {

    final RegistrationRecord registrationRecord =
        opaqueProvider.finalizeRegistrationRequest(
            hardenedPin,
            pinCredentialResponse.blind(),
            pinCredentialResponse.responseData(),
            clientContextConfiguration.getServerIdentity(),
            clientId);

    performPakeFinalization(
        context,
        registrationRecord.getEncoded(),
        clientContextConfiguration,
        jweCodec,
        new PinRegistrationStrategy(authorization));
  }

  @Override
  public void changePin(final String pin, final String context, final String oldPin)
      throws PakeSessionException, PakeAuthenticationException, ServiceResponseException {
    if (oldPin == null) {
      throw new PakeSessionException("A PIN change request MUST contain an old PIN");
    }
    log.debug("Performing PIN change");

    final ClientContextConfiguration clientContextConfiguration = contextInfoMap.get(context);
    if (clientContextConfiguration == null) {
      throw new PakeSessionException(String.format("The context %s is not available", context));
    }

    // Re-authenticate with the old, still valid PIN
    log.debug(
        "Deleting old session for context {} in order to create a new session with old PIN",
        context);
    deleteContextSessions(context);
    String pakeSessionId = createSession(oldPin, context).getPakeSessionId();
    log.debug("Created new session for context {} with old PIN", context);

    JweCodec jweCodec =
        jweCodecFactory.forUserAuthentication(sessionRegistry.getPakeSession(pakeSessionId));

    final byte[] hPin = hardenPin(pin, clientContextConfiguration);

    PinCredentialResponse pinCredentialResponse =
        initiateChangePin(hPin, clientContextConfiguration, context, jweCodec, pakeSessionId);

    completeChangePin(
        hPin, pinCredentialResponse, clientContextConfiguration, context, pakeSessionId, jweCodec);

    log.debug("PIN change completed for context {}", context);

    // Removing all protected sessions for this context that has been created under the old PIN
    deleteContextSessions(context);
  }

  private PinCredentialResponse initiateChangePin(
      byte[] hardenedPin,
      ClientContextConfiguration clientContextConfiguration,
      String context,
      JweCodec jweCodec,
      String pakeSessionId)
      throws PakeAuthenticationException, ServiceResponseException {

    final RegistrationRequestResult registrationRequestBundle =
        opaqueProvider.createRegistrationRequest(hardenedPin);

    PakeResponsePayload evaluateResponsePayload =
        performPakeEvaluation(
            context,
            ServiceType.PIN_CHANGE,
            registrationRequestBundle.registrationRequest().getEncoded(),
            pakeSessionId,
            clientContextConfiguration,
            jweCodec);

    return new PinCredentialResponse(
        evaluateResponsePayload.getResponseData(), registrationRequestBundle.blind());
  }

  private void completeChangePin(
      byte[] hardenedPin,
      PinCredentialResponse pinCredentialResponse,
      ClientContextConfiguration clientContextConfiguration,
      String context,
      String pakeSessionId,
      JweCodec jweCodec)
      throws PakeAuthenticationException, ServiceResponseException {

    final RegistrationRecord registrationRecord =
        opaqueProvider.finalizeRegistrationRequest(
            hardenedPin,
            pinCredentialResponse.blind(),
            pinCredentialResponse.responseData(),
            clientContextConfiguration.getServerIdentity(),
            clientId);

    performPakeFinalization(
        context,
        registrationRecord.getEncoded(),
        clientContextConfiguration,
        jweCodec,
        new PinChangeStrategy(pakeSessionId));
  }

  @Override
  public ServiceResult userAuthenticatedService(
      final String serviceTypeId,
      final ExchangePayload<?> payload,
      final String context,
      final String sessionId)
      throws PakeSessionException,
      ServiceResponseException,
      PakeAuthenticationException,
      ServiceRequestException {

    final ServiceType serviceType = serviceTypeRegistry.getServiceType(serviceTypeId);
    if (EncryptOption.user != serviceType.encryptKey()) {
      throw new ServiceRequestException("This service type must use encrypted payload");
    }

    final ClientContextConfiguration clientContextConfiguration = contextInfoMap.get(context);
    if (clientContextConfiguration == null) {
      throw new PakeSessionException(String.format("The context %s is not available", context));
    }

    JweCodec jweCodec =
        jweCodecFactory.forUserAuthentication(sessionRegistry.getPakeSession(sessionId));

    return requestService(
        serviceType, payload, context, sessionId, jweCodec, clientContextConfiguration);
  }

  @Override
  public ServiceResult deviceAuthenticatedService(
      final String serviceTypeId, final ExchangePayload<?> payload, final String context)
      throws PakeSessionException,
      ServiceResponseException,
      PakeAuthenticationException,
      ServiceRequestException {

    final ServiceType serviceType = serviceTypeRegistry.getServiceType(serviceTypeId);
    if (EncryptOption.device != serviceType.encryptKey()) {
      throw new ServiceRequestException(
          "This service type must use device authenticated encryption");
    }

    final ClientContextConfiguration clientContextConfiguration = contextInfoMap.get(context);
    if (clientContextConfiguration == null) {
      throw new PakeSessionException(String.format("The context %s is not available", context));
    }

    JweCodec jweCodec = jweCodecFactory.forDeviceAuthentication(clientContextConfiguration);

    return requestService(
        serviceType, payload, context, null, jweCodec, clientContextConfiguration);
  }

  @Override
  public ServiceResult deviceAuthenticatedService(final String serviceType, final String context)
      throws PakeSessionException,
      ServiceResponseException,
      PakeAuthenticationException,
      ServiceRequestException {
    return deviceAuthenticatedService(serviceType, new NullPayload(), context);
  }

  private ServiceResult requestService(
      final ServiceType serviceType,
      final ExchangePayload<?> payload,
      final String context,
      String pakeSessionId,
      JweCodec jweCodec,
      ClientContextConfiguration clientContextConfiguration)
      throws ServiceResponseException, PakeAuthenticationException {

    String nonce = Hex.toHexString(OpaqueUtils.random(32));
    ServiceRequest serviceRequest =
        ServiceRequest.builder()
            .clientID(clientId)
            .context(context)
            .serviceType(serviceType.id())
            .kid(clientContextConfiguration.getKid())
            .nonce(nonce)
            .pakeSessionId(pakeSessionId)
            .build();

    String serviceExchange;
    try {
      serviceExchange =
          ServiceExchangeBuilder.build(
              serviceType,
              serviceRequest,
              payload,
              clientContextConfiguration.getSigningParams(),
              jweCodec.jweEncryptor());
    } catch (JsonProcessingException | JOSEException e) {
      throw new PakeAuthenticationException("Failed to generate service request");
    }

    final ServiceResult serviceResult =
        ServiceResponseParser.parse(
            connector.requestService(serviceExchange),
            jweCodec.jweDecryptor(),
            clientContextConfiguration.getServerVerifier());

    // If the service request was an error. Return the error response
    if (!serviceResult.success()) {
      return serviceResult;
    }
    // Verify the success service response
    verifyServiceResult(serviceResult, nonce);
    return serviceResult;
  }

  private PakeResponsePayload performPakeEvaluation(
      final String context,
      final String serviceTypeId,
      final byte[] requestData,
      final String pakeSessionId,
      ClientContextConfiguration clientContextConfiguration,
      JweCodec jweCodec)
      throws ServiceResponseException, PakeAuthenticationException {

    String nonce = Hex.toHexString(OpaqueUtils.random(32));

    PakeRequestPayload pakeEvaluatePayload =
        PakeRequestPayload.builder()
            .protocol(PakeProtocol.opaque)
            .state(evaluate)
            .requestData(requestData)
            .build();

    final ServiceRequest pakeRequestWrapper =
        ServiceRequest.builder()
            .clientID(clientId)
            .kid(clientContextConfiguration.getKid())
            .context(context)
            .serviceType(serviceTypeId)
            .nonce(nonce)
            .pakeSessionId(pakeSessionId)
            .build();

    return sendRequest(
        context,
        serviceTypeId,
        clientContextConfiguration,
        jweCodec,
        nonce,
        pakeEvaluatePayload,
        pakeRequestWrapper);
  }

  private PakeResponsePayload performPakeFinalization(
      final String context,
      final byte[] requestData,
      ClientContextConfiguration clientContextConfiguration,
      JweCodec jweCodec,
      PakeOperationStrategy operationStrategy)
      throws ServiceResponseException, PakeAuthenticationException {

    String nonce = Hex.toHexString(OpaqueUtils.random(32));

    PakeRequestPayload pakeFinalizePayload = operationStrategy.createFinalizePayload(requestData);
    ServiceRequest pakeRequestWrapper =
        operationStrategy.createServiceRequest(
            clientId, clientContextConfiguration.getKid(), context, nonce);

    return sendRequest(
        context,
        operationStrategy.getServiceTypeId(),
        clientContextConfiguration,
        jweCodec,
        nonce,
        pakeFinalizePayload,
        pakeRequestWrapper);
  }

  private PakeResponsePayload sendRequest(
      String context,
      String serviceTypeId,
      ClientContextConfiguration clientContextConfiguration,
      JweCodec jweCodec,
      String nonce,
      PakeRequestPayload pakeEvaluatePayload,
      ServiceRequest pakeRequestWrapper)
      throws ServiceResponseException, PakeAuthenticationException {
    try {
      final String request =
          ServiceExchangeBuilder.build(
              serviceTypeRegistry.getServiceType(serviceTypeId),
              pakeRequestWrapper,
              pakeEvaluatePayload,
              clientContextConfiguration.getSigningParams(),
              jweCodec.jweEncryptor());

      final ServiceResult result =
          ServiceResponseParser.parse(
              connector.requestService(request),
              jweCodec.jweDecryptor(),
              clientContextConfiguration.getServerVerifier());

      if (result.success()) {
        verifyServiceResult(result, nonce);
      } else {
        throw new ServiceResponseException(
            String.format(
                "Service request of type '%s' under context '%s' failed with http code %d, "
                    + "error code %s and error message: %s",
                serviceTypeId,
                context,
                result.httpStatusCode(),
                result.errorResponse().getErrorCode(),
                result.errorResponse().getMessage()));
      }

      return StaticResources.TIME_STAMP_SECONDS_MAPPER.readValue(
          result.decryptedPayload(), PakeResponsePayload.class);
    } catch (IOException | JOSEException e) {
      throw new PakeAuthenticationException("Failed to create session: " + e.getMessage(), e);
    }
  }

  private void verifyServiceResult(final ServiceResult result, final String nonce)
      throws ServiceResponseException {

    final ServiceResponse serviceResponse = result.serviceResponse();

    final String responseNonce = serviceResponse.getNonce();
    if (!nonce.equals(responseNonce)) {
      throw new ServiceResponseException(
          String.format("Response nonce mismatch. Expected %s, received %s", nonce, responseNonce));
    }

    final Instant responseIat = serviceResponse.getIat();
    if (Instant.now().isAfter(responseIat.plusSeconds(10))) {
      throw new ServiceResponseException("Response is issued after 10 seconds from now");
    }
    if (Instant.now().isBefore(responseIat.minusSeconds(30))) {
      throw new ServiceResponseException("Response is more than 30 seconds old");
    }

    if (serviceResponse.getServiceData() == null) {
      throw new ServiceResponseException("Service data is null");
    }
  }

  private byte[] hardenPin(String pin, ClientContextConfiguration clientContextConfiguration) {
    return pinHardening.process(
        pin, clientContextConfiguration.getContextKeyPair().getPrivate(), 32);
  }
}
