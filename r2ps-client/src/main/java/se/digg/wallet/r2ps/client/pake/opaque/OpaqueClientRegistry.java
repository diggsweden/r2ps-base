package se.digg.wallet.r2ps.client.pake.opaque;

public interface OpaqueClientRegistry {

  void putClientRegistrationRecord(byte[] sessionId, byte[] registrationRecord);

  byte[] getClientRegistrationRecord(byte[] sessionId);

}
