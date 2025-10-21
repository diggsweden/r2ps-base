package se.digg.wallet.r2ps.client.pake.opaque;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.digg.crypto.opaque.client.OpaqueClient;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ClientOpaqueEntity {

  private String clientIdentity;
  private OpaqueClient opaqueClient;

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {
    private ClientOpaqueEntity clientOpaqueEntity;

    public Builder() {
      this.clientOpaqueEntity = new ClientOpaqueEntity();
    }

    public Builder clientIdentity(String clientIdentity) {
      this.clientOpaqueEntity.setClientIdentity(clientIdentity);
      return this;
    }

    public Builder opaqueClient(OpaqueClient opaqueClient) {
      this.clientOpaqueEntity.setOpaqueClient(opaqueClient);
      return this;
    }

    public ClientOpaqueEntity build() {
      return this.clientOpaqueEntity;
    }
  }

}
