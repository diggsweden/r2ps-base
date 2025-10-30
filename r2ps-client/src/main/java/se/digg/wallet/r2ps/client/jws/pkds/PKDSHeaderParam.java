package se.digg.wallet.r2ps.client.jws.pkds;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Map;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.digg.wallet.r2ps.commons.serializers.X509CertificateDeserializer;
import se.digg.wallet.r2ps.commons.serializers.X509CertificateSerializer;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class PKDSHeaderParam {

  public static final ObjectMapper OBJECT_MAPPER;

  static {
    OBJECT_MAPPER =
        JsonMapper.builder()
            .serializationInclusion(JsonInclude.Include.NON_NULL)
            .addModule(
                new SimpleModule()
                    .addSerializer(JWK.class, new JWKSerializer())
                    .addDeserializer(JWK.class, new JWKDeserializer())
                    .addSerializer(Base64URL.class, new Base64URLSerializer())
                    .addDeserializer(Base64URL.class, new Base64URLDeserializer())
                    .addSerializer(X509Certificate.class, new X509CertificateSerializer())
                    .addDeserializer(X509Certificate.class, new X509CertificateDeserializer()))
            .build();
  }

  @JsonProperty("suite")
  private PKDSSuite suite;

  @JsonProperty("rpk")
  private PKDSPublicKey recipientPublicKey;

  @JsonProperty("ppk")
  private PKDSPublicKey producerPublicKey;

  @JsonProperty("params")
  private PKDSParams params;

  @JsonProperty("length")
  private Integer length;

  @JsonIgnore
  public Map<String, Object> toJsonObject() {
    return OBJECT_MAPPER.convertValue(this, Map.class);
  }

  @JsonIgnore
  public String toJson() throws IOException {
    try {
      return OBJECT_MAPPER.writeValueAsString(this);
    } catch (JacksonException e) {
      throw new IOException("Failed to serialize PKDS header", e);
    }
  }

  @JsonIgnore
  public static PKDSHeaderParam parse(final String json) throws IOException {
    try {
      return OBJECT_MAPPER.readValue(json, PKDSHeaderParam.class);
    } catch (JacksonException e) {
      throw new IOException("Failed to parse PKDS header", e);
    }
  }

  @JsonIgnore
  public static PKDSHeaderParam parse(final Map<?, ?> jsonObject) throws IOException {
    return OBJECT_MAPPER.convertValue(jsonObject, PKDSHeaderParam.class);
  }

  private static class JWKSerializer extends JsonSerializer<JWK> {
    @Override
    public void serialize(
        final JWK jwk,
        final JsonGenerator jsonGenerator,
        final SerializerProvider serializerProvider)
        throws IOException {
      Map<String, Object> jsonObject = jwk.toJSONObject();
      jsonGenerator.writeObject(jsonObject);
    }
  }

  private static class JWKDeserializer extends JsonDeserializer<JWK> {
    @Override
    public JWK deserialize(
        final JsonParser jsonParser, final DeserializationContext deserializationContext)
        throws IOException {
      try {
        JsonNode node = jsonParser.getCodec().readTree(jsonParser);
        String jwkJson = node.toString();
        return JWK.parse(jwkJson);
      } catch (ParseException e) {
        throw new IOException("Failed to deserialize JWK", e);
      }
    }
  }

  private static class Base64URLSerializer extends JsonSerializer<Base64URL> {
    @Override
    public void serialize(
        final Base64URL base64URL,
        final JsonGenerator jsonGenerator,
        final SerializerProvider serializerProvider)
        throws IOException {
      jsonGenerator.writeString(base64URL.toString());
    }
  }

  private static class Base64URLDeserializer extends JsonDeserializer<Base64URL> {
    @Override
    public Base64URL deserialize(
        final JsonParser jsonParser, final DeserializationContext deserializationContext)
        throws IOException {
      return new Base64URL(jsonParser.getValueAsString());
    }
  }
}
