package se.digg.wallet.r2ps.client.jws.pkds;

import com.nimbusds.jose.JWSAlgorithm;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Arrays;

@Getter
@AllArgsConstructor
public enum HSPKDSAlgorithm {
  HS256_PKDS(new JWSAlgorithm("HS256-PKDS")),
  HS384_PKDS(new JWSAlgorithm("HS384-PKDS")),
  HS512_PKDS(new JWSAlgorithm("HS512-PKDS"));

  private final JWSAlgorithm alg;

  public static HSPKDSAlgorithm fromJWSAlgorithm(final JWSAlgorithm alg) {
    return Arrays.stream(HSPKDSAlgorithm.values())
        .filter(hspkdsAlgorithm -> hspkdsAlgorithm.alg.equals(alg))
        .findFirst()
        .orElseThrow(() -> new IllegalArgumentException("Unsupported JWS algorithm: " + alg));
  }

  public static HSPKDSAlgorithm fromString(final String alg) {
    return Arrays.stream(values())
        .filter(hspkdsAlgorithm -> hspkdsAlgorithm.alg.getName().equals(alg))
        .findFirst()
        .orElseThrow(() -> new IllegalArgumentException("Unsupported JWS algorithm: " + alg));
  }
}
