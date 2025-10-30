package se.digg.wallet.r2ps.commons.dto.payload;

import com.fasterxml.jackson.core.JsonProcessingException;
import java.io.IOException;
import lombok.NoArgsConstructor;

@NoArgsConstructor
public class NullPayload implements ExchangePayload<NullPayload> {
  @Override
  public byte[] serialize() throws JsonProcessingException {
    return new byte[0];
  }

  @Override
  public NullPayload deserialize(final byte[] data) throws IOException {
    if (null == data || data.length == 0) {
      return new NullPayload();
    }
    throw new IOException("Incompatible data for a null payload - expected empty data");
  }
}
