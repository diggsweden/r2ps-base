package se.digg.wallet.r2ps.server.pake.opaque;

import lombok.Data;
import lombok.NoArgsConstructor;
import se.digg.crypto.opaque.server.ServerState;
import se.digg.wallet.r2ps.commons.pake.opaque.PakeSessionRegistryRecord;

import java.time.Duration;
import java.time.Instant;

@Data
@NoArgsConstructor
public class ServerPakeRecord implements PakeSessionRegistryRecord {

  private String clientId;
  private String kid;
  private String pakeSessionId;
  private String context;
  private Instant creationTime;
  private Instant expirationTime;
  private byte[] sessionKey;
  private ServerState serverState;

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {
    private final ServerPakeRecord serverPakeRecord;

    public Builder() {
      this.serverPakeRecord = new ServerPakeRecord();
      this.serverPakeRecord.setCreationTime(Instant.now());
    }

    public Builder clientId(final String clientId) {
      this.serverPakeRecord.setClientId(clientId);
      return this;
    }

    public Builder kid(final String kid) {
      this.serverPakeRecord.setKid(kid);
      return this;
    }

    public Builder pakeSessionId(final String pakeSessionId) {
      this.serverPakeRecord.setPakeSessionId(pakeSessionId);
      return this;
    }

    public Builder context(final String context) {
      this.serverPakeRecord.setContext(context);
      return this;
    }

    public Builder expiryDuration(final Duration recordDuration) {
      this.serverPakeRecord.setExpirationTime(Instant.now().plus(recordDuration));
      return this;
    }

    public Builder serverState(final ServerState serverState) {
      this.serverPakeRecord.setServerState(serverState);
      return this;
    }

    public ServerPakeRecord build() {
      return this.serverPakeRecord;
    }
  }
}
