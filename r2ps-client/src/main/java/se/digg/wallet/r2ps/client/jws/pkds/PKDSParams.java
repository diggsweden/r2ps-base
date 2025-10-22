package se.digg.wallet.r2ps.client.jws.pkds;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jose.util.Base64URL;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class PKDSParams {
  @JsonProperty("info")
  private Base64URL info;
  @JsonProperty("salt")
  private Base64URL salt;
}
