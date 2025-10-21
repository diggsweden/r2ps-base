package se.digg.wallet.r2ps.server.service;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.security.PublicKey;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ClientPublicKeyRecord {

  /** The public key of this record */
  @JsonProperty("public_key")
  PublicKey publicKey;

  /** The key identifier of this record */
  @JsonProperty("kid")
  String kid;

  /** List of contexts where this key is allowed to be used */
  @JsonProperty("context")
  List<String> supportedContexts;

  /**
   * Authorization code that is present only on initial PIN registration to validate PIN
   * registration request
   */
  @JsonProperty("authorization")
  byte[] authorization;
}

