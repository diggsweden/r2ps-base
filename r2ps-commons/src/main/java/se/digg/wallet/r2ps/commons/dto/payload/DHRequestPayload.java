package se.digg.wallet.r2ps.commons.dto.payload;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.digg.wallet.r2ps.commons.StaticResources;

import java.io.IOException;
import java.security.PublicKey;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DHRequestPayload implements ExchangePayload<DHRequestPayload>, HSMParams {

  @JsonProperty(KEY_IDENTIFIER)
  String kid;

  @JsonProperty(PUBLIC_KEY)
  PublicKey publicKey;

  @Override
  public byte[] serialize() throws JsonProcessingException {
    return StaticResources.SERVICE_EXCHANGE_OBJECT_MAPPER.writeValueAsBytes(this);
  }

  @Override
  public DHRequestPayload deserialize(final byte[] data) throws IOException {
    return StaticResources.SERVICE_EXCHANGE_OBJECT_MAPPER.readValue(data, DHRequestPayload.class);
  }
}
