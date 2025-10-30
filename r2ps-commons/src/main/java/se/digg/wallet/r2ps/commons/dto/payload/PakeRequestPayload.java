package se.digg.wallet.r2ps.commons.dto.payload;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import java.io.IOException;
import java.time.Duration;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.digg.wallet.r2ps.commons.StaticResources;
import se.digg.wallet.r2ps.commons.dto.PakeProtocol;
import se.digg.wallet.r2ps.commons.dto.PakeState;

/**
 * Represents the payload for a Password Authenticated Key Exchange (PAKE) request. This class
 * extends {@link ExchangePayload}, inheriting its base properties such as a nonce and creation
 * timestamp, while defining additional fields specific to PAKE protocol requests.
 *
 * <p>The payload includes: - The PAKE protocol being used. - The current state of the PAKE
 * operation, such as evaluation or finalization. - Optional authorization data, typically used for
 * PIN registrations or resets. - Protocol-specific data associated with the current state.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PakeRequestPayload implements ExchangePayload<PakeRequestPayload> {

  /** Identifies the PAKE protocol */
  @JsonProperty("protocol")
  private PakeProtocol protocol;

  /**
   * Identifies the PAKE state which determines the data content. E.g., evaluate or finalize for
   * OPAQUE
   */
  @JsonProperty("state")
  private PakeState state;

  /** Optional authorization data required for initial PIN registrations or PIN resets */
  @JsonProperty("authorization")
  private byte[] authorization;

  @JsonProperty("task")
  private String task;

  @JsonProperty("session_duration")
  private Duration sessionDuration;

  /** The PAKE request data as defined by the PAKE state */
  @JsonProperty("req")
  byte[] requestData;

  @JsonIgnore
  @Override
  public byte[] serialize() throws JsonProcessingException {
    return StaticResources.SERVICE_EXCHANGE_OBJECT_MAPPER.writeValueAsBytes(this);
  }

  @JsonIgnore
  @Override
  public PakeRequestPayload deserialize(final byte[] data) throws IOException {
    return StaticResources.SERVICE_EXCHANGE_OBJECT_MAPPER.readValue(data, PakeRequestPayload.class);
  }
}
