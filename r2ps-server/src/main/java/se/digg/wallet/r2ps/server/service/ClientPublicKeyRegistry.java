package se.digg.wallet.r2ps.server.service;

public interface ClientPublicKeyRegistry {

  /**
   * Retrieves the public key record associated with a specific client and key identifier.
   *
   * @param clientId the unique identifier of the client whose public key record is to be retrieved
   * @param kid the key identifier of the specific public key record to retrieve
   * @return the {@link ClientPublicKeyRecord} corresponding to the given client ID and key ID, or
   *         null if no matching record is found
   */
  ClientPublicKeyRecord getClientPublicKeyRecord(String clientId, String kid);

  /**
   * Registers a client's public key record in the system.
   *
   * @param clientId the unique identifier of the client
   * @param clientPublicKeyRecord the public key record to register for the client
   */
  void registerClientPublicKey(String clientId, ClientPublicKeyRecord clientPublicKeyRecord);

  /**
   * Deletes the public key record associated with the specified client and key identifier (KID).
   *
   * @param clientId the unique identifier of the client whose public key record is to be deleted
   * @param kid the key identifier of the specific public key record to delete
   */
  void deleteClientPublicKeyRecord(String clientId, String kid);

  /**
   * Sets the authorization code for a client's public key record.
   *
   * @param clientId the unique identifier of the client
   * @param kid the key identifier associated with the public key
   * @param authorizationCode the authorization code to be set, as a byte array
   * @return true if the authorization code was successfully set, false otherwise
   */
  boolean setAuthorizationCode(String clientId, String kid, byte[] authorizationCode);
}
