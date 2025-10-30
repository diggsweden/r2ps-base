package se.digg.wallet.r2ps.commons;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import se.digg.wallet.r2ps.commons.serializers.DurationDeserializer;
import se.digg.wallet.r2ps.commons.serializers.DurationSerializer;
import se.digg.wallet.r2ps.commons.serializers.InstantDeserializer;
import se.digg.wallet.r2ps.commons.serializers.InstantSerializer;
import se.digg.wallet.r2ps.commons.serializers.PublicKeyDeserializer;
import se.digg.wallet.r2ps.commons.serializers.PublicKeySerializer;

public class StaticResources {

  public static final ObjectMapper OBJECT_MAPPER;
  public static final ObjectMapper TIME_STAMP_SECONDS_MAPPER;
  public static final ObjectMapper PUBLIC_KEY_OBJECT_MAPPER;
  public static final ObjectMapper SERVICE_EXCHANGE_OBJECT_MAPPER;

  static {
    OBJECT_MAPPER =
        JsonMapper.builder().serializationInclusion(JsonInclude.Include.NON_NULL).build();

    PUBLIC_KEY_OBJECT_MAPPER =
        JsonMapper.builder()
            .serializationInclusion(JsonInclude.Include.NON_NULL)
            .addModule(createSimpleModule(true, false, false))
            .build();

    TIME_STAMP_SECONDS_MAPPER =
        JsonMapper.builder()
            .serializationInclusion(JsonInclude.Include.NON_NULL)
            .addModule(new JavaTimeModule())
            .configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, true)
            .configure(SerializationFeature.WRITE_DATE_TIMESTAMPS_AS_NANOSECONDS, false)
            .configure(DeserializationFeature.READ_DATE_TIMESTAMPS_AS_NANOSECONDS, false)
            .addModule(createSimpleModule(false, true, true))
            .build();

    SERVICE_EXCHANGE_OBJECT_MAPPER =
        JsonMapper.builder()
            .serializationInclusion(JsonInclude.Include.NON_NULL)
            .addModule(new JavaTimeModule())
            .configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, true)
            .configure(SerializationFeature.WRITE_DATE_TIMESTAMPS_AS_NANOSECONDS, false)
            .configure(DeserializationFeature.READ_DATE_TIMESTAMPS_AS_NANOSECONDS, false)
            .addModule(createSimpleModule(true, true, true))
            .build();
  }

  private static SimpleModule createSimpleModule(
      boolean publicKeySerialization, boolean instantSerialization, boolean durationSerialization) {
    SimpleModule module = new SimpleModule();
    if (instantSerialization) {
      module
          .addSerializer(Instant.class, new InstantSerializer())
          .addDeserializer(Instant.class, new InstantDeserializer());
    }
    if (durationSerialization) {
      module
          .addSerializer(Duration.class, new DurationSerializer())
          .addDeserializer(Duration.class, new DurationDeserializer());
    }
    if (publicKeySerialization) {
      module
          .addSerializer(PublicKey.class, new PublicKeySerializer())
          .addDeserializer(PublicKey.class, new PublicKeyDeserializer());
    }
    return module;
  }
}
