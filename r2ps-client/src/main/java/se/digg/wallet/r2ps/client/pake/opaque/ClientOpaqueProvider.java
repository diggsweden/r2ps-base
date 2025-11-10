package se.digg.wallet.r2ps.client.pake.opaque;

import static java.nio.charset.StandardCharsets.UTF_8;

import se.digg.crypto.opaque.client.ClientKeyExchangeResult;
import se.digg.crypto.opaque.client.ClientState;
import se.digg.crypto.opaque.client.OpaqueClient;
import se.digg.crypto.opaque.client.RegistrationFinalizationResult;
import se.digg.crypto.opaque.client.RegistrationRequestResult;
import se.digg.crypto.opaque.dto.KE1;
import se.digg.crypto.opaque.dto.RegistrationRecord;
import se.digg.crypto.opaque.error.DeriveKeyPairErrorException;
import se.digg.crypto.opaque.error.DeserializationException;
import se.digg.crypto.opaque.error.EvelopeRecoveryException;
import se.digg.crypto.opaque.error.InvalidInputException;
import se.digg.crypto.opaque.error.ServerAuthenticationException;
import se.digg.wallet.r2ps.commons.exception.PakeAuthenticationException;

public class ClientOpaqueProvider {

  private final OpaqueClient opaqueClient;

  public ClientOpaqueProvider(OpaqueClient opaqueClient) {
    this.opaqueClient = opaqueClient;
  }

  public RegistrationRequestResult createRegistrationRequest(byte[] pin)
      throws PakeAuthenticationException {
    try {
      return opaqueClient.createRegistrationRequest(pin);
    } catch (DeriveKeyPairErrorException e) {
      throw new PakeAuthenticationException("Error registering PIN: " + e.getMessage(), e);
    }
  }

  public RegistrationRecord finalizeRegistrationRequest(
      byte[] pin, byte[] blind, byte[] registrationResponse, String serverIdentity, String clientId)
      throws PakeAuthenticationException {
    try {
      RegistrationFinalizationResult registrationFinalizationResult =
          opaqueClient.finalizeRegistrationRequest(
              pin,
              blind,
              registrationResponse,
              serverIdentity.getBytes(UTF_8),
              clientId.getBytes(UTF_8));
      return registrationFinalizationResult.registrationRecord();
    } catch (DeserializationException | DeriveKeyPairErrorException | InvalidInputException e) {
      throw new PakeAuthenticationException("Error registering PIN: " + e.getMessage(), e);
    }
  }

  public KE1 authenticationEvaluate(byte[] pin, ClientState clientState)
      throws PakeAuthenticationException {
    try {
      return opaqueClient.generateKe1(pin, clientState);
    } catch (DeriveKeyPairErrorException e) {
      throw new PakeAuthenticationException("Failed to create session: " + e.getMessage(), e);
    }
  }

  public ClientKeyExchangeResult authenticationFinalize(
      byte[] ke2, ClientState clientState, String serverIdentity, String clientId)
      throws PakeAuthenticationException {

    try {
      return opaqueClient.generateKe3(
          clientId.getBytes(UTF_8), serverIdentity.getBytes(UTF_8), ke2, clientState);
    } catch (EvelopeRecoveryException
        | DeriveKeyPairErrorException
        | DeserializationException
        | ServerAuthenticationException
        | InvalidInputException e) {
      throw new PakeAuthenticationException(
          "Authentication failed with the presented PIN and client key: %s" + e.getMessage(), e);
    }
  }
}
