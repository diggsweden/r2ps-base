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
public class ByteArrayPayload implements ExchangePayload<ByteArrayPayload> {

  /** The service data as defined by service type */
  private byte[] byteArrayValue;

  @Override
  public byte[] serialize() throws JsonProcessingException {
    return this.byteArrayValue;
  }

  @Override
  public ByteArrayPayload deserialize(final byte[] data) throws IOException {
    return new ByteArrayPayload(data);
  }
}
