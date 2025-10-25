package se.digg.wallet.r2ps.commons.dto.payload;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.digg.wallet.r2ps.commons.StaticResources;

import java.io.IOException;
import java.time.Instant;

/**
 * Represents the payload of a PAKE (Password-Authenticated Key Exchange) response. This class
 * extends the {@code Payload} class and is used to encapsulate the response data associated with a
 * PAKE session, as defined by the server.
 * <p>
 * The PAKE response payload includes the unique session ID assigned by the server and the response
 * data associated with the current PAKE state in the request.
 * <p>
 * This response is valid for all PAKE exchanges. This includes PIN registrations, PIN change and
 * Authentication.
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class PakeResponsePayload implements ExchangePayload<PakeResponsePayload> {

  /** The PAKE session ID assigned by the server */
  @JsonProperty("pake_session_id")
  private String pakeSessionId;
  /** The session task recognized by the server bound to this pake session ID */
  @JsonProperty("task")
  private String task;
  /** PAKE response data as defined by the PAKE state in the request */
  @JsonProperty("resp")
  private byte[] responseData;
  @JsonProperty("msg")
  private String message;
  @JsonProperty("session_expiration_time")
  private Instant sessionExpirationTime;

  @JsonIgnore
  @Override
  public byte[] serialize() throws JsonProcessingException {
    return StaticResources.SERVICE_EXCHANGE_OBJECT_MAPPER.writeValueAsBytes(this);
  }

  @JsonIgnore
  @Override
  public PakeResponsePayload deserialize(final byte[] data) throws IOException {
    return StaticResources.SERVICE_EXCHANGE_OBJECT_MAPPER.readValue(data,
        PakeResponsePayload.class);
  }
}
