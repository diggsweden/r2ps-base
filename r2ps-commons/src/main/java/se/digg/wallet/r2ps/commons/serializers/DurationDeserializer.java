package se.digg.wallet.r2ps.commons.serializers;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;

public class DurationDeserializer extends JsonDeserializer<Duration> {
  @Override
  public Duration deserialize(final JsonParser jsonParser,
      final DeserializationContext deserializationContext)
      throws IOException, JacksonException {
    return Duration.ofSeconds(jsonParser.getLongValue());
  }
}
