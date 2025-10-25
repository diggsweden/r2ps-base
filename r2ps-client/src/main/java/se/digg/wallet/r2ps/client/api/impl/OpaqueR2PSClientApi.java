package se.digg.wallet.r2ps.client.api.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;
import se.digg.crypto.opaque.OpaqueUtils;
import se.digg.crypto.opaque.client.ClientState;
import se.digg.crypto.opaque.client.OpaqueClient;
import se.digg.crypto.opaque.client.RegistrationRequestResult;
import se.digg.crypto.opaque.dto.KE1;
import se.digg.crypto.opaque.dto.KE3;
import se.digg.crypto.opaque.dto.RegistrationRecord;
import se.digg.crypto.opaque.error.DeriveKeyPairErrorException;
import se.digg.crypto.opaque.error.DeserializationException;
import se.digg.crypto.opaque.error.InvalidInputException;
import se.digg.wallet.r2ps.client.api.ClientContextConfiguration;
import se.digg.wallet.r2ps.commons.dto.HttpResponse;
import se.digg.wallet.r2ps.client.api.R2PSClientApi;
import se.digg.wallet.r2ps.client.api.ServiceExchangeConnector;
import se.digg.wallet.r2ps.client.api.ServiceResult;
import se.digg.wallet.r2ps.commons.dto.EncryptOption;
import se.digg.wallet.r2ps.commons.dto.ErrorResponse;
import se.digg.wallet.r2ps.commons.dto.JWEEncryptionParams;
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
import se.digg.wallet.r2ps.client.pake.PinHardening;
import se.digg.wallet.r2ps.client.pake.impl.ECPrivateKeyDHPinHardening;
import se.digg.wallet.r2ps.client.pake.opaque.ClientOpaqueEntity;
import se.digg.wallet.r2ps.client.pake.opaque.ClientOpaqueProvider;
import se.digg.wallet.r2ps.client.pake.opaque.ClientPakeRecord;
import se.digg.wallet.r2ps.commons.utils.ServiceExchangeFactory;
import se.digg.wallet.r2ps.commons.StaticResources;
import se.digg.wallet.r2ps.commons.utils.Utils;

import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.interfaces.ECPrivateKey;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static se.digg.wallet.r2ps.commons.dto.PakeState.EVALUATE;
import static se.digg.wallet.r2ps.commons.dto.PakeState.FINALIZE;

@Slf4j
public class OpaqueR2PSClientApi implements R2PSClientApi {

  private final String clientId;
  private final ClientOpaqueProvider opaqueProvider;
  private final ServiceExchangeConnector connector;
  private final ServiceExchangeFactory serviceExchangeFactory;
  private final ServiceTypeRegistry serviceTypeRegistry;
  /** A map keyed by context, holding info about that context */
  private final Map<String, ClientContextConfiguration> contextInfoMap;
  private final PinHardening pinHardening;

  @Setter
  private int encryptKeyLengthBytes = 32;
  @Setter
  private EncryptionMethod encryptionMethod = EncryptionMethod.A256GCM;

  public OpaqueR2PSClientApi(OpaqueRpsOpsConfiguration configuration) {
    this.clientId = configuration.getClientIdentity();
    OpaqueClient opaqueClient = configuration.getOpaqueConfiguration().getOpaqueClient();
    ClientOpaqueEntity clientOpaqueEntity =
        new ClientOpaqueEntity(configuration.getClientIdentity(), opaqueClient);
    this.opaqueProvider =
        new ClientOpaqueProvider(clientOpaqueEntity, configuration.getClientPakeSessionRegistry(),
            configuration.getSessionDuration());
    this.connector = configuration.getServiceExchangeConnector();
    this.serviceTypeRegistry = configuration.getServiceTypeRegistry();
    this.serviceExchangeFactory = new ServiceExchangeFactory();
    this.contextInfoMap = configuration.getContextConfigurationMap();
    this.pinHardening = new ECPrivateKeyDHPinHardening(
        configuration.getOpaqueConfiguration().getHashToCurveProfile());
  }

  @Override
  public PakeResponsePayload createSession(final String pin, final String context)
      throws PakeSessionException, ServiceResponseException, PakeAuthenticationException {
    return createSession(pin, context, null, null);
  }

  @Override
  public PakeResponsePayload createSession(final String pin, final String context, String task, Duration requestedDuration)
      throws PakeSessionException, ServiceResponseException, PakeAuthenticationException {
    String pakeSessionId = null;
    try {
      log.debug("Creating session for context {}", context);
      if (!contextInfoMap.containsKey(context)) {
        throw new PakeSessionException(String.format("The context %s is not available", context));
      }
      final ClientContextConfiguration clientContextConfiguration = contextInfoMap.get(context);
      JWEEncryptionParams encryptionParams =
          getESDHEncryptionParams(clientContextConfiguration, true);
      JWEEncryptionParams decryptionParams =
          getESDHEncryptionParams(clientContextConfiguration, false);
      final byte[] hPin = hardenPin(pin, clientContextConfiguration);
      ClientState clientState = new ClientState();
      String nonce = Hex.toHexString(OpaqueUtils.random(32));
      final KE1 ke1 = opaqueProvider.authenticationEvaluate(hPin, clientState);
      PakeRequestPayload pakeEvaluatePayload = PakeRequestPayload.builder()
          .protocol(PakeProtocol.opaque)
          .state(EVALUATE)
          .requestData(ke1.getEncoded())
          .build();
      final ServiceRequest pakeRequestWrapper = ServiceRequest.builder()
          .clientID(clientId)
          .kid(clientContextConfiguration.getKid())
          .context(context)
          .serviceType(ServiceType.AUTHENTICATE)
          .nonce(nonce)
          .build();
      final String pakeEvaluateRequest =
          serviceExchangeFactory.createServiceExchangeObject(
              serviceTypeRegistry.getServiceType(ServiceType.AUTHENTICATE),
              pakeRequestWrapper,
              pakeEvaluatePayload,
              clientContextConfiguration.getSigningParams(), encryptionParams);
      final ServiceResult evaluateResult = parseServiceResponse(
          connector.requestService(pakeEvaluateRequest), decryptionParams,
          clientContextConfiguration, ServiceType.AUTHENTICATE);
      verifyServiceResult(evaluateResult, ServiceType.AUTHENTICATE, nonce, context);
      PakeResponsePayload evaluateResponsePayload =
          StaticResources.TIME_STAMP_SECONDS_MAPPER.readValue(
              evaluateResult.decryptedPayload(),
              PakeResponsePayload.class
          );
      pakeSessionId = evaluateResponsePayload.getPakeSessionId();
      final byte[] ke2 = evaluateResponsePayload.getResponseData();
      final KE3 ke3;
      try {
        ke3 = opaqueProvider.authenticationFinalize(
            ke2, pakeSessionId, context, clientContextConfiguration.getKid(), clientState,
            clientContextConfiguration.getServerIdentity(), task);
      } catch (Exception e) {
        throw new PakeAuthenticationException(
            String.format("Authentication failed with the presented PIN and client key: %s",
                e.getMessage()), e);
      }

      nonce = Hex.toHexString(OpaqueUtils.random(32));
      PakeRequestPayload pakeFinalizePayload = PakeRequestPayload.builder()
          .protocol(PakeProtocol.opaque)
          .state(FINALIZE)
          .task(task)
          .sessionDuration(requestedDuration)
          .requestData(ke3.getEncoded())
          .build();
      pakeRequestWrapper.setPakeSessionId(pakeSessionId);
      pakeRequestWrapper.setNonce(nonce);
      pakeRequestWrapper.setServiceData(null);
      final String pakeFinalizeRequest =
          serviceExchangeFactory.createServiceExchangeObject(
              serviceTypeRegistry.getServiceType(ServiceType.AUTHENTICATE),
              pakeRequestWrapper, pakeFinalizePayload,
              clientContextConfiguration.getSigningParams(), encryptionParams);
      final ServiceResult finalizeResult = parseServiceResponse(
          connector.requestService(pakeFinalizeRequest), decryptionParams,
          clientContextConfiguration, ServiceType.AUTHENTICATE);
      verifyServiceResult(finalizeResult, ServiceType.AUTHENTICATE, nonce, context);

      PakeResponsePayload responsePayload =
          StaticResources.TIME_STAMP_SECONDS_MAPPER.readValue(finalizeResult.decryptedPayload(),
              PakeResponsePayload.class);
      log.debug("Created session for context {} with sessionID {}", context, pakeSessionId);
      // Update the session expiration time in the registry with the expiration time from the server and add task.
      final Instant sessionExpirationTime = responsePayload.getSessionExpirationTime();
      if (sessionExpirationTime == null) {
        log.debug("No session expiration time from server. Abort session");
        opaqueProvider.getSessionRegistry().deletePakeSession(pakeSessionId);
        throw new PakeSessionException("No session expiration time from server. Abort session");
      }
      // Update the session registry
      final ClientPakeRecord pakeSession = opaqueProvider.getSessionRegistry().getPakeSession(pakeSessionId);
      pakeSession.setExpirationTime(sessionExpirationTime);
      pakeSession.setSessionTaskId(responsePayload.getTask());
      opaqueProvider.getSessionRegistry().updatePakeSession(pakeSession);

      return responsePayload;
    } catch (PakeSessionException | ServiceResponseException | PakeAuthenticationException e) {
      if (pakeSessionId != null) {
        opaqueProvider.getSessionRegistry().deletePakeSession(pakeSessionId);
      }
      throw e;
    } catch (IOException | DeriveKeyPairErrorException | JOSEException e) {
      if (pakeSessionId != null) {
        opaqueProvider.getSessionRegistry().deletePakeSession(pakeSessionId);
      }
      throw new PakeAuthenticationException("Failed to create session: " + e.getMessage(), e);
    }
  }

  @Override
  public void deleteContextSessions(final String context) throws PakeSessionException {
    if (!contextInfoMap.containsKey(context)) {
      log.debug("The context {} is not registered in the context registry.", context);
      throw new PakeSessionException(
          String.format("Failed to delete context session for context '%s' No such context",
              context));
    }
    final ClientContextConfiguration clientContextConfiguration = contextInfoMap.get(context);
    final List<ClientPakeRecord> pakeSession =
        opaqueProvider.getSessionRegistry()
            .getPakeSessions(clientId, clientContextConfiguration.getKid(), context);
    // Attempting to delete sessions from local registry
    if (!pakeSession.isEmpty()) {
      for (ClientPakeRecord clientPakeRecord : pakeSession) {
        log.debug("Deleting session for context {} with session id {}", context,
            clientPakeRecord.getPakeSessionId());
        opaqueProvider.getSessionRegistry().deletePakeSession(clientPakeRecord.getPakeSessionId());
      }
    } else {
      log.debug("No active session for context {}. Nothing to delete", context);
    }
    // Attempting to delete all context sessions from the server
    try {
      deviceAuthenticatedService(ServiceType.SESSION_CONTEXT_END, new NullPayload(), context);
    } catch (PakeAuthenticationException | ServiceResponseException | ServiceRequestException e) {
      log.warn("Failed to interact with server to delete context sessions for context {}", context,
          e);
    }
  }

  @Override
  public void deleteSession(final String sessionId) throws PakeSessionException {
    log.debug("Deleting session with session id {}", sessionId);

    // fetching session because we need the context
    final ClientPakeRecord pakeSession =
        opaqueProvider.getSessionRegistry().getPakeSession(sessionId);
    if (pakeSession == null) {
      log.debug("Session {} is not present", sessionId);
      return;
    }
    String context = pakeSession.getContext();

    opaqueProvider.getSessionRegistry().deletePakeSession(sessionId);
    log.debug("Deleted session {} for context {} from local registry", sessionId, context);

    try {
      deviceAuthenticatedService(ServiceType.SESSION_END, new StringPayload(sessionId), context);
      log.debug("Deleted session {} for context {} from server", sessionId, context);
    } catch (PakeAuthenticationException | ServiceResponseException | ServiceRequestException e) {
      log.warn("Failed to interact with server to delete session {}", sessionId, e);
    }
  }

  @Override
  public void changePin(final String pin, final String context, final String oldPin)
      throws PakeSessionException, PakeAuthenticationException, ServiceResponseException {
    try {
      registerOrChangePin(pin, context, null, oldPin);
    } catch (InvalidInputException | IOException | DeriveKeyPairErrorException | JOSEException |
        DeserializationException e) {
      throw new PakeAuthenticationException("Error changing PIN: " + e.getMessage(), e);
    }
  }

  @Override
  public void registerPin(final String pin, final String context, final byte[] authorization)
      throws PakeSessionException, PakeAuthenticationException {
    try {
      registerOrChangePin(pin, context, authorization, null);
    } catch (InvalidInputException | ServiceResponseException | IOException |
        DeriveKeyPairErrorException |
        JOSEException | DeserializationException e) {
      throw new PakeAuthenticationException("Error registering PIN: " + e.getMessage(), e);
    }

  }

  private void registerOrChangePin(final String pin, String context, final byte[] authorization,
      final String oldPin)
      throws PakeSessionException, InvalidInputException,
      ServiceResponseException, IOException, DeriveKeyPairErrorException, JOSEException,
      DeserializationException, PakeAuthenticationException {
    if (!contextInfoMap.containsKey(context)) {
      throw new PakeSessionException(String.format("The context %s is not available", context));
    }
    if (authorization == null && oldPin == null) {
      throw new PakeSessionException(
          "A PIN registration request MUST contain either an authorization or an old PIN");
    }
    if (authorization != null && oldPin != null) {
      throw new PakeSessionException(
          "A PIN registration request must not contain both an authorization and an old PIN");
    }
    boolean initialRegistration = authorization != null;
    log.debug("Performing PIN registration with initial registration: {}", initialRegistration);
    String pakeSessionId = null;
    if (!initialRegistration) {
      // Re-authenticate with the old, still valid PIN
      log.debug("Deleting old session for context {} in order to create a new session with old PIN",
          context);
      this.deleteContextSessions(context);
      pakeSessionId = this.createSession(oldPin, context).getPakeSessionId();
      log.debug("Created new session for context {} with old PIN", context);
    }

    final ClientContextConfiguration clientContextConfiguration = contextInfoMap.get(context);
    final byte[] hPin = hardenPin(pin, clientContextConfiguration);
    String nonce = Hex.toHexString(OpaqueUtils.random(32));
    final RegistrationRequestResult registrationRequestBundle =
        opaqueProvider.createRegistrationRequest(hPin);
    PakeRequestPayload registrationEvaluatePayload = PakeRequestPayload.builder()
        .protocol(PakeProtocol.opaque)
        .state(EVALUATE)
        .requestData(registrationRequestBundle.registrationRequest().getEncoded())
        .build();
    String serviceTypeId =
        initialRegistration ? ServiceType.PIN_REGISTRATION : ServiceType.PIN_CHANGE;
    final ServiceRequest pakeRequestWrapper = ServiceRequest.builder()
        .clientID(clientId)
        .kid(clientContextConfiguration.getKid())
        .pakeSessionId(pakeSessionId) // Will be null on initial registration
        .context(context)
        .serviceType(serviceTypeId)
        .nonce(nonce)
        .build();
    JWEEncryptionParams encryptionParams;
    JWEEncryptionParams decryptionParams;
    if (initialRegistration) {
      encryptionParams = getESDHEncryptionParams(clientContextConfiguration, true);
      decryptionParams = getESDHEncryptionParams(clientContextConfiguration, false);
    } else {
      encryptionParams = new JWEEncryptionParams(
          new SecretKeySpec(opaqueProvider.getSessionRegistry().getPakeSession(pakeSessionId)
              .getSessionKey(), "AES"),
          encryptionMethod);
      decryptionParams = encryptionParams;
    }
    final String registrationEvaluateRequest =
        serviceExchangeFactory.createServiceExchangeObject(
            serviceTypeRegistry.getServiceType(serviceTypeId), pakeRequestWrapper,
            registrationEvaluatePayload,
            clientContextConfiguration.getSigningParams(), encryptionParams);
    final ServiceResult registrationEvaluateResult = parseServiceResponse(
        connector.requestService(registrationEvaluateRequest), decryptionParams,
        clientContextConfiguration,
        serviceTypeId);
    verifyServiceResult(registrationEvaluateResult,
        initialRegistration ? ServiceType.PIN_REGISTRATION : ServiceType.PIN_CHANGE, nonce,
        context);
    PakeResponsePayload registrationEvaluateResponsePayload =
        StaticResources.TIME_STAMP_SECONDS_MAPPER.readValue(
            registrationEvaluateResult.decryptedPayload(), PakeResponsePayload.class);
    final byte[] pakeRegistrationResponse = registrationEvaluateResponsePayload.getResponseData();

    nonce = Hex.toHexString(OpaqueUtils.random(32));
    final RegistrationRecord registrationRecord =
        opaqueProvider.finalizeRegistrationRequest(hPin, registrationRequestBundle.blind(),
            pakeRegistrationResponse,
            clientContextConfiguration.getServerIdentity());
    PakeRequestPayload registrationFinalizePayload = PakeRequestPayload.builder()
        .protocol(PakeProtocol.opaque)
        .state(FINALIZE)
        .authorization(authorization) // Will always be null on PIN change
        .requestData(registrationRecord.getEncoded())
        .build();
    pakeRequestWrapper.setNonce(nonce);
    pakeRequestWrapper.setServiceData(null);

    final String registrationFinalizeRequest =
        serviceExchangeFactory.createServiceExchangeObject(
            serviceTypeRegistry.getServiceType(serviceTypeId), pakeRequestWrapper,
            registrationFinalizePayload,
            clientContextConfiguration.getSigningParams(), encryptionParams);
    final ServiceResult registrationFinalizeResult = parseServiceResponse(
        connector.requestService(registrationFinalizeRequest), decryptionParams,
        clientContextConfiguration,
        serviceTypeId);
    verifyServiceResult(registrationFinalizeResult,
        initialRegistration ? ServiceType.PIN_REGISTRATION : ServiceType.PIN_CHANGE, nonce,
        context);
    log.debug("PIN registration completed for context {}", context);
    if (!initialRegistration) {
      // Removing all protected sessions for this context that has been created under the old PIN
      this.deleteContextSessions(context);
    }
  }

  @Override
  public ServiceResult userAuthenticatedService(final String serviceTypeId,
      final ExchangePayload<?> payload,
      final String context,
      final String sessionId)
      throws PakeSessionException, ServiceResponseException, PakeAuthenticationException,
      ServiceRequestException {
    final ServiceType serviceType = serviceTypeRegistry.getServiceType(serviceTypeId);
    if (EncryptOption.USER != serviceType.encryptKey()) {
      throw new ServiceRequestException("This service type must use encrypted payload");
    }
    return requestService(serviceType, payload, context, sessionId);
  }

  @Override
  public ServiceResult deviceAuthenticatedService(final String serviceTypeId,
      final ExchangePayload<?> payload,
      final String context)
      throws PakeSessionException, ServiceResponseException, PakeAuthenticationException,
      ServiceRequestException {
    final ServiceType serviceType = serviceTypeRegistry.getServiceType(serviceTypeId);
    if (EncryptOption.DEVICE != serviceType.encryptKey()) {
      throw new ServiceRequestException("This service type must use device authenticated encryption");
    }
    return requestService(serviceType, payload, context, null);
  }

  @Override
  public ServiceResult deviceAuthenticatedService(final String serviceType, final String context)
      throws PakeSessionException, ServiceResponseException, PakeAuthenticationException,
      ServiceRequestException {
    return deviceAuthenticatedService(serviceType, new NullPayload(), context);
  }

  private ServiceResult requestService(final ServiceType serviceType,
      final ExchangePayload<?> payload,
      final String context, String sessionId)
      throws PakeSessionException, ServiceResponseException, PakeAuthenticationException,
      ServiceRequestException {
    try {
      if (!contextInfoMap.containsKey(context)) {
        throw new PakeSessionException(String.format("The context %s is not available", context));
      }
      final ClientContextConfiguration clientContextConfiguration = contextInfoMap.get(context);
      final EncryptOption encryptOption = serviceType.encryptKey();
      String pakeSessionId = null;
      JWEEncryptionParams encryptionParams = null;
      JWEEncryptionParams decryptionParams = null;
      if (encryptOption.equals(EncryptOption.USER)) {
        final ClientPakeRecord pakeSession =
            opaqueProvider.getSessionRegistry().getPakeSession(sessionId);
        if (pakeSession == null) {
          throw new PakeSessionException(
              String.format("Failed to request service for context %s. No active session",
                  context));
        }
        pakeSessionId = pakeSession.getPakeSessionId();
        if (pakeSession.getSessionKey() == null) {
          throw new PakeSessionException(
              String.format("No session key available for context %s", context));
        }
        encryptionParams = new JWEEncryptionParams(
            new SecretKeySpec(pakeSession.getSessionKey(), "AES"),
            encryptionMethod);
        decryptionParams = encryptionParams;
      }
      if (encryptOption.equals(EncryptOption.DEVICE)) {
        encryptionParams = getESDHEncryptionParams(clientContextConfiguration, true);
        decryptionParams = getESDHEncryptionParams(clientContextConfiguration, false);
      }
      String nonce = Hex.toHexString(OpaqueUtils.random(32));
      ServiceRequest serviceRequest = ServiceRequest.builder()
          .clientID(clientId)
          .context(context)
          .serviceType(serviceType.id())
          .kid(clientContextConfiguration.getKid())
          .nonce(nonce)
          .pakeSessionId(pakeSessionId)
          .build();

      final String serviceExchange =
          serviceExchangeFactory.createServiceExchangeObject(serviceType, serviceRequest,
              payload,
              clientContextConfiguration.getSigningParams(),
              encryptionParams);
      final ServiceResult serviceResult =
          parseServiceResponse(connector.requestService(serviceExchange), decryptionParams,
              clientContextConfiguration,
              serviceType.id());
      // If the service request was an error. Return the error response
      if (!serviceResult.success()) {
        return serviceResult;
      }
      // Verify the success service response
      verifyServiceResult(serviceResult, serviceType.id(), nonce, context);
      return serviceResult;
    } catch (JsonProcessingException | JOSEException e) {
      throw new PakeAuthenticationException("Failed to generate service request");
    }
  }

  private JWEEncryptionParams getESDHEncryptionParams(
      final ClientContextConfiguration clientContextConfiguration, boolean encryptOption)
      throws PakeSessionException {
    if (encryptOption) {
      return new JWEEncryptionParams(clientContextConfiguration.getServerPublicKey(),
          encryptionMethod);
    }
    return new JWEEncryptionParams(
        (ECPrivateKey) clientContextConfiguration.getContextKeyPair().getPrivate(),
        encryptionMethod);
  }

  private ServiceResult parseServiceResponse(final HttpResponse httpResponse,
      JWEEncryptionParams encryptionParams,
      ClientContextConfiguration clientContextConfiguration, final String serviceTypeId)
      throws ServiceResponseException {
    if (httpResponse == null) {
      throw new ServiceResponseException("No service response from server");
    }
    final String responseData = httpResponse.responseData();
    if (responseData == null) {
      throw new ServiceResponseException("No service response data from server");
    }
    try {
      final int responseCode = httpResponse.responseCode();
      boolean success = responseCode == 200;
      ServiceResponse serviceResponse = null;
      ErrorResponse errorResponse = null;
      byte[] decryptedPayload = null;
      if (success) {
        JWSObject jwsObject = JWSObject.parse(responseData);
        if (!jwsObject.verify(clientContextConfiguration.getServerVerifier())) {
          throw new ServiceResponseException("Failed to verify service response signature");
        }
        jwsObject.getPayload().toJSONObject();
        serviceResponse = StaticResources.TIME_STAMP_SECONDS_MAPPER.convertValue(
            jwsObject.getPayload().toJSONObject(),
            ServiceResponse.class);
        if (Instant.now().isAfter(serviceResponse.getIat().plusSeconds(30))) {
          throw new ServiceResponseException("Service response is more than 30 seconds old");
        }
        final byte[] serviceData = serviceResponse.getServiceData();
        final ServiceType serviceType = serviceTypeRegistry.getServiceType(serviceTypeId);
        decryptedPayload = serviceData;
        if (EncryptOption.USER == serviceType.encryptKey()) {
          decryptedPayload = Utils.decryptJWE(serviceData, encryptionParams);
        }
        if (EncryptOption.DEVICE == serviceType.encryptKey()) {
          decryptedPayload =
              Utils.decryptJWE_ECDH(serviceData, encryptionParams.staticPrivateRecipientKey());
        }
        if (log.isDebugEnabled()) {
          log.debug("Client received service response with valid signature:\n{}",
              StaticResources.TIME_STAMP_SECONDS_MAPPER.writerWithDefaultPrettyPrinter()
                  .writeValueAsString(serviceResponse));

          log.debug("Service data in service response{}:\n{}",
              EncryptOption.USER == serviceType.encryptKey() ? " after decryption" : "",
              Utils.prettyPrintByteArray(decryptedPayload));
        }
      } else {
        errorResponse =
            StaticResources.TIME_STAMP_SECONDS_MAPPER.readValue(responseData, ErrorResponse.class);
        if (log.isDebugEnabled()) {
          log.debug("Received error response with http status code: {}\n{}", responseCode,
              StaticResources.TIME_STAMP_SECONDS_MAPPER.writerWithDefaultPrettyPrinter()
                  .writeValueAsString(errorResponse));
        }
      }
      return new ServiceResult(serviceResponse, decryptedPayload, errorResponse, success,
          responseCode);
    } catch (IOException | ParseException | JOSEException e) {
      throw new ServiceResponseException("Failed to parse service response", e);
    }
  }

  private void verifyServiceResult(final ServiceResult result, final String serviceType,
      final String nonce,
      final String context) throws ServiceResponseException {
    if (!result.success()) {
      throw new ServiceResponseException(String.format(
          "Service request of type '%s' under context '%s' failed with http code %d, error code %s and error message: %s",
          serviceType, context, result.httpStatusCode(), result.errorResponse().getErrorCode(),
          result.errorResponse().getMessage()));
    }
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
    return pinHardening.process(pin, clientContextConfiguration.getContextKeyPair().getPrivate(),
        32);
  }
}
