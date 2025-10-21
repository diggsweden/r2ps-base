package se.digg.wallet.r2ps.commons.dto.payload;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import lombok.AllArgsConstructor;
import lombok.Getter;
import se.digg.wallet.r2ps.commons.StaticResources;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@AllArgsConstructor
public class JsonPayload implements ExchangePayload<JsonPayload> {

  @Getter
  Map<String, Object> data;

  public JsonPayload() {
    this.data = new HashMap<>();
  }

  public Object get(final String key) {
    return data.get(key);
  }

  public <T extends Object> T get(final String key, final Class<T> clazz) {
    return clazz.cast(data.get(key));
  }

  public boolean containsKey(final String key) {
    return data.containsKey(key);
  }

  public Set<Map.Entry<String, Object>> entrySet() {
    return data.entrySet();
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {
    private final JsonPayload jsonPayload;

    public Builder() {
      this.jsonPayload = new JsonPayload();
    }

    public Builder add(final String key, final Object value) {
      this.jsonPayload.data.put(key, value);
      return this;
    }

    public JsonPayload build() {
      return this.jsonPayload;
    }
  }



  @Override
  public byte[] serialize() throws JsonProcessingException {
    return StaticResources.SERVICE_EXCHANGE_OBJECT_MAPPER.writeValueAsBytes(this.data);
  }

  @Override
  public JsonPayload deserialize(final byte[] data) throws IOException {
    return new JsonPayload(StaticResources.SERVICE_EXCHANGE_OBJECT_MAPPER.readValue(data,
        new TypeReference<>() {
        }));
  }
}
