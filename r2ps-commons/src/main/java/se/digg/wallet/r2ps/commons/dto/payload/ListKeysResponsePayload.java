package se.digg.wallet.r2ps.commons.dto.payload;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import java.io.IOException;
import java.security.PublicKey;
import java.time.Instant;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.digg.wallet.r2ps.commons.StaticResources;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ListKeysResponsePayload implements ExchangePayload<ListKeysResponsePayload> {

  @JsonProperty("key_info")
  List<KeyInfo> keyInfo;

  @JsonIgnore
  @Override
  public byte[] serialize() throws JsonProcessingException {
    return StaticResources.SERVICE_EXCHANGE_OBJECT_MAPPER.writeValueAsBytes(this);
  }

  @JsonIgnore
  @Override
  public ListKeysResponsePayload deserialize(final byte[] data) throws IOException {
    return StaticResources.SERVICE_EXCHANGE_OBJECT_MAPPER.readValue(
        data, ListKeysResponsePayload.class);
  }

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  @Builder
  public static class KeyInfo {
    @JsonProperty("kid")
    String kid;

    @JsonProperty("curve_name")
    String curveName;

    @JsonProperty("creation_time")
    Instant creationTime;

    @JsonProperty("public_key")
    PublicKey publicKey;
  }
}
