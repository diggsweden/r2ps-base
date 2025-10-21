package se.digg.wallet.r2ps.client.pake.opaque;

import lombok.Data;
import lombok.NoArgsConstructor;
import se.digg.wallet.r2ps.commons.pake.opaque.PakeSessionRegistryRecord;

import java.time.Duration;
import java.time.Instant;

@Data
@NoArgsConstructor
public class ClientPakeRecord implements PakeSessionRegistryRecord {

  private String clientId;
  private String context;
  private String kid;
  private String pakeSessionId;
  private Instant creationTime;
  private Instant expirationTime;
  private byte[] sessionKey;
  private byte[] exportKey;

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {
    private ClientPakeRecord clientPakeRecord;

    public Builder() {
      this.clientPakeRecord = new ClientPakeRecord();
      this.clientPakeRecord.setCreationTime(Instant.now());
    }

    public Builder clientId(final String clientId) {
      this.clientPakeRecord.setClientId(clientId);
      return this;
    }

    public Builder context(final String context) {
      this.clientPakeRecord.setContext(context);
      return this;
    }

    public Builder pakeSessionId(final String pakeSessionId) {
      this.clientPakeRecord.setPakeSessionId(pakeSessionId);
      return this;
    }

    public Builder expiryDuration(final Duration recordDuration) {
      this.clientPakeRecord.setExpirationTime(Instant.now().plus(recordDuration));
      return this;
    }

    public Builder kid(final String kid) {
      this.clientPakeRecord.setKid(kid);
      return this;
    }

    public Builder sessionKey(final byte[] sessionKey) {
      this.clientPakeRecord.setSessionKey(sessionKey);
      return this;
    }

    public Builder exportKey(final byte[] exportKey) {
      this.clientPakeRecord.setExportKey(exportKey);
      return this;
    }

    public ClientPakeRecord build() {
      return this.clientPakeRecord;
    }
  }
}
