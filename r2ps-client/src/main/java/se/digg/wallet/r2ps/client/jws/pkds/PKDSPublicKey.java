package se.digg.wallet.r2ps.client.jws.pkds;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;
import java.security.cert.X509Certificate;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class PKDSPublicKey {

  @JsonProperty("kid")
  private String keyId;

  @JsonProperty("jwk")
  private JWK jwk;

  @JsonProperty("x5c")
  private X509Certificate x509Certificate;

  @JsonProperty("x5t#S256")
  private Base64URL x509CertificateSHA256Thumbprint;
}
