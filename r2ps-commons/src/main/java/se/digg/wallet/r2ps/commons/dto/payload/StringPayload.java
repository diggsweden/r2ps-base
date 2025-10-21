package se.digg.wallet.r2ps.commons.dto.payload;

import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.IOException;

/**
 * This class provides a simple payload type for service exchanges that only contains an opaque data
 * field that may contain any data structure defined by the service type. This payload class is
 * suitable in particular for simple stateless service requests such as the PING_ID service
 * request.
 */
@AllArgsConstructor
@NoArgsConstructor
@Data
public class StringPayload implements ExchangePayload<StringPayload> {

  /** The service data as defined by service type */
  private String stringValue;

  @Override
  public byte[] serialize() throws JsonProcessingException {
    return stringValue.getBytes();
  }

  @Override
  public StringPayload deserialize(final byte[] data) throws IOException {
    return new StringPayload(new String(data));
  }

}
