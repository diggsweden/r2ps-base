package se.digg.wallet.r2ps.server.service.pinauthz.impl;

import se.digg.wallet.r2ps.server.service.ClientPublicKeyRecord;
import se.digg.wallet.r2ps.server.service.ClientPublicKeyRegistry;
import se.digg.wallet.r2ps.server.service.pinauthz.PinAuthorization;

import java.util.Arrays;

public class CodeMatchPinAuthorization implements PinAuthorization {

  private final ClientPublicKeyRegistry clientPublicKeyRegistry;

  public CodeMatchPinAuthorization(final ClientPublicKeyRegistry clientPublicKeyRegistry) {
    this.clientPublicKeyRegistry = clientPublicKeyRegistry;
  }

  @Override
  public boolean authorize(final byte[] authorizationCode, final String kid,
      final String clientId) {
    final ClientPublicKeyRecord clientPublicKeyRecord =
        clientPublicKeyRegistry.getClientPublicKeyRecord(clientId, kid);
    if (clientPublicKeyRecord == null) {
      return false;
    }
    if (authorizationCode != null && authorizationCode.length > 0 && clientPublicKeyRecord.getAuthorization() != null
        && clientPublicKeyRecord.getAuthorization().length > 0) {
      boolean success = Arrays.equals(authorizationCode, clientPublicKeyRecord.getAuthorization());
      // Reset authorization code
      clientPublicKeyRecord.setAuthorization(null);
      return success;
    }
    return false;
  }

  @Override
  public boolean clearAuthorization(final String clientId, final String kid) {
    final ClientPublicKeyRecord clientPublicKeyRecord =
        clientPublicKeyRegistry.getClientPublicKeyRecord(clientId, kid);
    if (clientPublicKeyRecord != null) {
      clientPublicKeyRecord.setAuthorization(null);
      return true;
    }
    return false;
  }
}
