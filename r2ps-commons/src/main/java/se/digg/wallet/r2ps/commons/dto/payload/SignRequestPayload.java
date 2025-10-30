package se.digg.wallet.r2ps.commons.dto.payload;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.digg.wallet.r2ps.commons.StaticResources;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SignRequestPayload implements ExchangePayload<SignRequestPayload>, HSMParams {

  @JsonProperty(KEY_IDENTIFIER)
  String kid;

  @JsonProperty(TBS_HASH)
  byte[] tbsHash;

  @JsonIgnore
  @Override
  public byte[] serialize() throws JsonProcessingException {
    return StaticResources.SERVICE_EXCHANGE_OBJECT_MAPPER.writeValueAsBytes(this);
  }

  @JsonIgnore
  @Override
  public SignRequestPayload deserialize(final byte[] data) throws IOException {
    return StaticResources.SERVICE_EXCHANGE_OBJECT_MAPPER.readValue(data, SignRequestPayload.class);
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {
    private final SignRequestPayload signRequestPayload;

    public Builder() {
      this.signRequestPayload = new SignRequestPayload();
    }

    public Builder kid(String kid) {
      this.signRequestPayload.setKid(kid);
      return this;
    }

    public Builder tbsHash(byte[] tbsHash) {
      this.signRequestPayload.setTbsHash(tbsHash);
      return this;
    }

    public Builder tbsHash(byte[] tbsData, String hashAlgorithm) throws NoSuchAlgorithmException {
      MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
      byte[] tbsHash = md.digest(tbsData);
      this.signRequestPayload.setTbsHash(tbsHash);
      return this;
    }

    public SignRequestPayload build() {
      return this.signRequestPayload;
    }
  }
}
