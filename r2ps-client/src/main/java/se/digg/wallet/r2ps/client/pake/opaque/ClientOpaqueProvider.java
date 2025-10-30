package se.digg.wallet.r2ps.client.pake.opaque;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
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
import se.digg.wallet.r2ps.commons.exception.PakeSessionException;
import se.digg.wallet.r2ps.commons.pake.opaque.PakeSessionRegistry;

public class ClientOpaqueProvider {

  private final ClientOpaqueEntity clientOpaqueEntity;
  @Getter private final PakeSessionRegistry<ClientPakeRecord> sessionRegistry;
  private final Duration recordDuration;

  public ClientOpaqueProvider(
      final ClientOpaqueEntity clientOpaqueEntity,
      final PakeSessionRegistry<ClientPakeRecord> sessionRegistry,
      Duration recordDuration) {
    this.clientOpaqueEntity = clientOpaqueEntity;
    this.sessionRegistry = sessionRegistry;
    this.recordDuration = recordDuration;
  }

  public RegistrationRequestResult createRegistrationRequest(byte[] pin)
      throws DeriveKeyPairErrorException {
    return clientOpaqueEntity.getOpaqueClient().createRegistrationRequest(pin);
  }

  public RegistrationRecord finalizeRegistrationRequest(
      byte[] pin, byte[] blind, byte[] registrationResponse, String serverIdentity)
      throws InvalidInputException, DeriveKeyPairErrorException, DeserializationException {
    final RegistrationFinalizationResult registrationFinalizationResult =
        clientOpaqueEntity
            .getOpaqueClient()
            .finalizeRegistrationRequest(
                pin,
                blind,
                registrationResponse,
                serverIdentity.getBytes(StandardCharsets.UTF_8),
                clientOpaqueEntity.getClientIdentity().getBytes(StandardCharsets.UTF_8));
    return registrationFinalizationResult.registrationRecord();
  }

  public KE1 authenticationEvaluate(byte[] pin, ClientState clientState)
      throws PakeSessionException, DeriveKeyPairErrorException {
    final KE1 ke1 = clientOpaqueEntity.getOpaqueClient().generateKe1(pin, clientState);
    return ke1;
  }

  public KE3 authenticationFinalize(
      byte[] ke2,
      String pakeSessionId,
      String context,
      String kid,
      ClientState clientState,
      String serverIdentity,
      String requestedTask)
      throws InvalidInputException,
          EvelopeRecoveryException,
          ServerAuthenticationException,
          DeriveKeyPairErrorException,
          DeserializationException {
    final ClientKeyExchangeResult clientKeyExchangeResult =
        clientOpaqueEntity
            .getOpaqueClient()
            .generateKe3(
                clientOpaqueEntity.getClientIdentity().getBytes(StandardCharsets.UTF_8),
                serverIdentity.getBytes(StandardCharsets.UTF_8),
                ke2,
                clientState);

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
