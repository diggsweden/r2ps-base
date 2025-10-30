package se.digg.wallet.r2ps.server.service.pinauthz;

public interface PinAuthorization {

  /**
   * Authorizes a client using the provided authorization code, key identifier (kid), and client ID.
   *
   * @param authorizationCode the authorization code as a byte array
   * @param kid the key identifier used for identification purposes
   * @param clientId the client ID requesting authorization
   * @return true if authorization is successful, false otherwise
   */
  boolean authorize(byte[] authorizationCode, String kid, String clientId);

  boolean clearAuthorization(String clientId, String kid);
}
