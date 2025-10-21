package se.digg.wallet.r2ps.commons.pake.opaque;

import java.time.Instant;

public interface PakeSessionRegistryRecord {

  String getPakeSessionId();

  String getClientId();

  String getKid();

  Instant getExpirationTime();

  String getContext();
}
