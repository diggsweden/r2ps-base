package se.digg.wallet.r2ps.server.service.impl;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import se.digg.wallet.r2ps.commons.dto.EncryptOption;
import se.digg.wallet.r2ps.commons.dto.ErrorCode;
import se.digg.wallet.r2ps.commons.dto.JWEEncryptionParams;
import se.digg.wallet.r2ps.commons.dto.JWSSigningParams;
import se.digg.wallet.r2ps.commons.dto.ServiceRequest;
import se.digg.wallet.r2ps.commons.dto.ServiceResponse;
import se.digg.wallet.r2ps.commons.dto.payload.ExchangePayload;
import se.digg.wallet.r2ps.commons.dto.servicetype.ServiceType;
import se.digg.wallet.r2ps.commons.dto.servicetype.ServiceTypeRegistry;
import se.digg.wallet.r2ps.commons.exception.ServiceRequestHandlingException;
import se.digg.wallet.r2ps.commons.pake.opaque.PakeSessionRegistry;
import se.digg.wallet.r2ps.server.pake.opaque.ServerPakeRecord;
import se.digg.wallet.r2ps.server.service.ClientPublicKeyRecord;
import se.digg.wallet.r2ps.server.service.ClientPublicKeyRegistry;
import se.digg.wallet.r2ps.server.service.OpaqueServiceRequestHandlerConfiguration;
import se.digg.wallet.r2ps.server.service.ReplayChecker;
import se.digg.wallet.r2ps.commons.utils.ServiceExchangeFactory;
import se.digg.wallet.r2ps.server.service.ServiceRequestHandler;
import se.digg.wallet.r2ps.commons.StaticResources;
import se.digg.wallet.r2ps.commons.utils.Utils;
import se.digg.wallet.r2ps.server.service.servicehandlers.ServiceTypeHandler;

import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

@Slf4j
public class DefaultServiceRequestHandler implements ServiceRequestHandler {

  private final ClientPublicKeyRegistry clientPublicKeyRegistry;
  private final List<ServiceTypeHandler> serviceTypeHandlers;
  private final ServiceTypeRegistry serviceTypeRegistry;
  private final ServiceExchangeFactory serviceExchangeFactory;
  private final JWSSigningParams serverSigningParams;
  private final ECPrivateKey esdhStaticPrivateKey;
  private final ReplayChecker replayChecker;
  private final EncryptionMethod encryptionMethod;
  private final PakeSessionRegistry<ServerPakeRecord> pakeSessionRegistry;

  // Defaults
  @Setter
  private Duration requestMaxAge = Duration.ofSeconds(30);

  public DefaultServiceRequestHandler(OpaqueServiceRequestHandlerConfiguration configuration)
      throws JOSEException {
    this.serverSigningParams = new JWSSigningParams(
        new ECDSASigner((ECPrivateKey) configuration.getServerKeyPair().getPrivate()),
        configuration.getServerJwsAlgorithm());
    this.esdhStaticPrivateKey = (ECPrivateKey) configuration.getServerKeyPair().getPrivate();
    this.encryptionMethod = configuration.getEncryptionMethod() == null ?
        EncryptionMethod.A256GCM :
        configuration.getEncryptionMethod();
    this.serviceTypeHandlers = configuration.getServiceTypeHandlers();
    this.pakeSessionRegistry = configuration.getServerPakeSessionRegistry();
    this.clientPublicKeyRegistry = configuration.getClientPublicKeyRegistry();
    this.serviceTypeRegistry = configuration.getServiceTypeRegistry();
    this.serviceExchangeFactory = new ServiceExchangeFactory();
    this.replayChecker = configuration.getReplayChecker();
  }

  @Override
  public String handleServiceRequest(final String serviceRequestJws)
      throws ServiceRequestHandlingException {
    try {
      JWSObject jwsObject = JWSObject.parse(serviceRequestJws);
      final ServiceRequest serviceRequest =
          StaticResources.TIME_STAMP_SECONDS_MAPPER.readValue(jwsObject.getPayload().toString(),
              ServiceRequest.class);

      if (serviceRequest.getContext() == null) {
        throw new ServiceRequestHandlingException("Not context is declared in the service request",
            ErrorCode.ILLEGAL_REQUEST_DATA);
      }

      if (replayChecker.isReplay(serviceRequest.getNonce())) {
        throw new ServiceRequestHandlingException("The request is a replay",
            ErrorCode.ACCESS_DENIED);
      }

      // Get publicKey and validate signature
      final String kid = serviceRequest.getKid();
      final String clientID = serviceRequest.getClientID();
      final ClientPublicKeyRecord clientPublicKeyRecord =
          clientPublicKeyRegistry.getClientPublicKeyRecord(clientID, kid);
      if (clientPublicKeyRecord == null) {
        throw new ServiceRequestHandlingException("No public key record available for this request",
            ErrorCode.ACCESS_DENIED);
      }
      final List<String> supportedContexts = clientPublicKeyRecord.getSupportedContexts();
      if (supportedContexts == null || !supportedContexts.contains(serviceRequest.getContext())) {
        throw new ServiceRequestHandlingException(
            "The indicated client public key is not supported for the selected context",
            ErrorCode.ACCESS_DENIED);
      }
      JWSVerifier verifier = getJwsVerifier(clientPublicKeyRecord);
      if (!jwsObject.verify(verifier)) {
        throw new ServiceRequestHandlingException("Invalid signature on service request",
            ErrorCode.ACCESS_DENIED);
      }

      final Instant issuedInstant = serviceRequest.getIat();
      if (issuedInstant == null) {
        throw new ServiceRequestHandlingException(
            "No issue time is declared in the service request", ErrorCode.ILLEGAL_REQUEST_DATA);
      }
      if (Instant.now().isAfter(issuedInstant.plus(requestMaxAge))) {
        throw new ServiceRequestHandlingException("request is too old", ErrorCode.ACCESS_DENIED);
      }

      // Signature is OK. Get other registry records
      final ServerPakeRecord pakeSession =
          pakeSessionRegistry.getPakeSession(serviceRequest.getPakeSessionId());
      final ServiceType serviceType =
          serviceTypeRegistry.getServiceType(serviceRequest.getServiceType());

      // Decrypt any encrypted data
      if (serviceRequest.getServiceData() == null) {
        throw new ServiceRequestHandlingException("No service data in request",
            ErrorCode.ILLEGAL_REQUEST_DATA);
      }

      JWEEncryptionParams encryptionParams = null;
      JWEEncryptionParams decryptionParams = null;
      byte[] decryptedPayload = serviceRequest.getServiceData();
      if (EncryptOption.user == serviceType.encryptKey()) {
        encryptionParams = createEncryptionParams(pakeSession);
        decryptionParams = encryptionParams;
        decryptedPayload = Utils.decryptJWE(serviceRequest.getServiceData(), decryptionParams);
      }
      if (EncryptOption.device == serviceType.encryptKey()) {
        encryptionParams = createESDHEncryptionParams(clientPublicKeyRecord, true);
        decryptionParams = createESDHEncryptionParams(clientPublicKeyRecord, false);
        decryptedPayload = Utils.decryptJWE_ECDH(serviceRequest.getServiceData(),
            decryptionParams.staticPrivateRecipientKey());
      }
      log.debug("Processing service data with encryption = {}:\n{}", serviceType.encryptKey(),
          new String(serviceRequest.getServiceData()));
      if (log.isDebugEnabled()) {
        log.debug("Server received service request with valid signature:\n{}",
            StaticResources.TIME_STAMP_SECONDS_MAPPER.writerWithDefaultPrettyPrinter()
                .writeValueAsString(serviceRequest));
        log.debug("Service data in service request{}:\n{}",
            encryptionParams == null ? "" : " after decryption",
            Utils.prettyPrintByteArray(decryptedPayload));
      }
      // Process request
      final ServiceTypeHandler serviceTypeHandler = serviceTypeHandlers.stream()
          .filter(handler -> handler.supports(serviceType, serviceRequest.getContext()))
          .findFirst().orElseThrow(() -> new ServiceRequestHandlingException(String.format(
              "The service type '%s' under context '%s' is not supported by any handler",
              serviceType.id(), serviceRequest.getContext()), ErrorCode.ACCESS_DENIED));
      ExchangePayload<?> responsePayload =
          serviceTypeHandler.processServiceRequest(serviceRequest, pakeSession,
              decryptedPayload, clientPublicKeyRecord, serviceType);

      // Create the service response
      ServiceResponse response =
          ServiceResponse.builder().nonce(serviceRequest.getNonce()).build();
      return serviceExchangeFactory.createServiceExchangeObject(serviceType, response,
          responsePayload, serverSigningParams, encryptionParams);
    } catch (ParseException | JOSEException | IOException e) {
      throw new ServiceRequestHandlingException("Error processing request: " + e.getMessage(), e,
          ErrorCode.ILLEGAL_REQUEST_DATA);
    }
  }

  private JWEEncryptionParams createESDHEncryptionParams(
      ClientPublicKeyRecord clientPublicKeyRecord, boolean encrypt) {
    if (encrypt) {
      return new JWEEncryptionParams((ECPublicKey) clientPublicKeyRecord.getPublicKey(),
          encryptionMethod);
    }
    return new JWEEncryptionParams(esdhStaticPrivateKey, encryptionMethod);
  }

  private JWEEncryptionParams createEncryptionParams(final ServerPakeRecord pakeSession)
      throws ServiceRequestHandlingException, ParseException, JOSEException {
    if (pakeSession == null) {
      throw new ServiceRequestHandlingException(
          "No matching PAKE session for decrypting this request", ErrorCode.ACCESS_DENIED);
    }
    if (Instant.now().isAfter(pakeSession.getExpirationTime())) {
      pakeSessionRegistry.purgeRecords();
      throw new ServiceRequestHandlingException("Pake session has expired",
          ErrorCode.ACCESS_DENIED);
    }
    return new JWEEncryptionParams(new SecretKeySpec(pakeSession.getSessionKey(), "AES"),
        encryptionMethod);
  }

  private static JWSVerifier getJwsVerifier(final ClientPublicKeyRecord clientPublicKeyRecord)
      throws ServiceRequestHandlingException, JOSEException {
    if (clientPublicKeyRecord == null) {
      throw new ServiceRequestHandlingException(
          "No client public key is registered that match the request", ErrorCode.ACCESS_DENIED);
    }

    final PublicKey clientPublicKey = clientPublicKeyRecord.getPublicKey();
    return switch (clientPublicKey.getAlgorithm()) {
      case "EC" -> new ECDSAVerifier((ECPublicKey) clientPublicKey);
      case "RSA" -> new RSASSAVerifier((RSAPublicKey) clientPublicKey);
      default -> throw new ServiceRequestHandlingException(
          "Unsupported public key algorithm: " + clientPublicKey.getAlgorithm(),
          ErrorCode.ILLEGAL_REQUEST_DATA);
    };
  }
}
