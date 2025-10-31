package se.digg.wallet.r2ps.client.pake.opaque;

import java.nio.charset.StandardCharsets;
import lombok.Getter;
import se.digg.crypto.opaque.client.ClientKeyExchangeResult;
import se.digg.crypto.opaque.client.ClientState;
import se.digg.crypto.opaque.client.RegistrationFinalizationResult;
import se.digg.crypto.opaque.client.RegistrationRequestResult;
import se.digg.crypto.opaque.dto.KE1;
import se.digg.crypto.opaque.dto.KE3;
import se.digg.crypto.opaque.dto.RegistrationRecord;
import se.digg.crypto.opaque.error.DeriveKeyPairErrorException;
import se.digg.crypto.opaque.error.DeserializationException;
import se.digg.crypto.opaque.error.EvelopeRecoveryException;
import se.digg.crypto.opaque.error.InvalidInputException;
import se.digg.crypto.opaque.error.ServerAuthenticationException;
import se.digg.wallet.r2ps.commons.exception.PakeAuthenticationException;
import se.digg.wallet.r2ps.commons.pake.opaque.PakeSessionRegistry;

public class ClientOpaqueProvider {

  private final ClientOpaqueEntity clientOpaqueEntity;
  @Getter private final PakeSessionRegistry<ClientPakeRecord> sessionRegistry;

  public ClientOpaqueProvider(
      final ClientOpaqueEntity clientOpaqueEntity,
      final PakeSessionRegistry<ClientPakeRecord> sessionRegistry) {
    this.clientOpaqueEntity = clientOpaqueEntity;
    this.sessionRegistry = sessionRegistry;
  }

  public RegistrationRequestResult createRegistrationRequest(byte[] pin)
      throws PakeAuthenticationException {
    try {
      return clientOpaqueEntity.getOpaqueClient().createRegistrationRequest(pin);
    } catch (DeriveKeyPairErrorException e) {
      throw new PakeAuthenticationException("Error registering PIN: " + e.getMessage(), e);
    }
  }

  public RegistrationRecord finalizeRegistrationRequest(
      byte[] pin, byte[] blind, byte[] registrationResponse, String serverIdentity)
      throws PakeAuthenticationException {
    try {
      RegistrationFinalizationResult registrationFinalizationResult =
          clientOpaqueEntity
              .getOpaqueClient()
              .finalizeRegistrationRequest(
                  pin,
                  blind,
                  registrationResponse,
                  serverIdentity.getBytes(StandardCharsets.UTF_8),
                  clientOpaqueEntity.getClientIdentity().getBytes(StandardCharsets.UTF_8));
      return registrationFinalizationResult.registrationRecord();
    } catch (DeserializationException | DeriveKeyPairErrorException | InvalidInputException e) {
      throw new PakeAuthenticationException("Error registering PIN: " + e.getMessage(), e);
    }
  }

  public KE1 authenticationEvaluate(byte[] pin, ClientState clientState)
      throws PakeAuthenticationException {
    try {
      return clientOpaqueEntity.getOpaqueClient().generateKe1(pin, clientState);
    } catch (DeriveKeyPairErrorException e) {
      throw new PakeAuthenticationException("Failed to create session: " + e.getMessage(), e);
    }
  }

  public KE3 authenticationFinalize(
      byte[] ke2,
      String pakeSessionId,
      String context,
      String kid,
      ClientState clientState,
      String serverIdentity,
      String requestedTask)
      throws PakeAuthenticationException {
    final ClientKeyExchangeResult clientKeyExchangeResult;
    try {
      clientKeyExchangeResult =
          clientOpaqueEntity
              .getOpaqueClient()
              .generateKe3(
                  clientOpaqueEntity.getClientIdentity().getBytes(StandardCharsets.UTF_8),
                  serverIdentity.getBytes(StandardCharsets.UTF_8),
                  ke2,
                  clientState);
    } catch (EvelopeRecoveryException
        | DeriveKeyPairErrorException
        | DeserializationException
        | ServerAuthenticationException
        | InvalidInputException e) {
      throw new PakeAuthenticationException(
          "Authentication failed with the presented PIN and client key: %s" + e.getMessage(), e);
    }

    ClientPakeRecord pakeSessionRecord =
        ClientPakeRecord.builder()
            .clientId(clientOpaqueEntity.getClientIdentity())
            .pakeSessionId(pakeSessionId)
            .kid(kid)
            .context(context)
            .requestedSessionTaskId(requestedTask)
            .sessionKey(clientKeyExchangeResult.sessionKey())
            .exportKey(clientKeyExchangeResult.exportKey())
            .build();
    sessionRegistry.addPakeSession(pakeSessionRecord);
    return clientKeyExchangeResult.ke3();
  }
}
