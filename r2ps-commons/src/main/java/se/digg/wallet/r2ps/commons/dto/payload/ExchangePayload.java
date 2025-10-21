package se.digg.wallet.r2ps.commons.dto.payload;

import com.fasterxml.jackson.core.JsonProcessingException;

import java.io.IOException;

/**
 * Represents the base interface for exchange payloads used for communicating JOSE protected data
 * between a client and a server.
 * <p>
 * The payload includes a unique identifier (nonce) and a creation timestamp (iat). Subclasses are
 * expected to define specific data fields and validation logic relevant to their use cases.
 * <p>
 * This class also provides an abstract builder implementation for constructing and validating
 * payload objects in a flexible and extensible manner. The builder ensures that essential
 * properties such as the nonce and timestamp are correctly set.
 */
public interface ExchangePayload<T extends ExchangePayload> {

  byte[] serialize() throws JsonProcessingException;

  T deserialize(byte[] data) throws IOException;
}
