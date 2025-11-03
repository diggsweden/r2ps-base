package se.digg.wallet.r2ps.client.api.impl;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.digg.wallet.r2ps.client.api.ClientContextConfiguration;
import se.digg.wallet.r2ps.client.api.ServiceExchangeConnector;
import se.digg.wallet.r2ps.client.pake.opaque.ClientPakeRecord;
import se.digg.wallet.r2ps.commons.dto.JWSSigningParams;
import se.digg.wallet.r2ps.commons.dto.servicetype.ServiceTypeRegistry;
import se.digg.wallet.r2ps.commons.pake.opaque.InMemoryPakeSessionRegistry;
import se.digg.wallet.r2ps.commons.pake.opaque.OpaqueConfiguration;
import se.digg.wallet.r2ps.commons.pake.opaque.PakeSessionRegistry;

@Data
@NoArgsConstructor
public class OpaqueR2PSConfiguration {

  // Parameters with builder default values
  /**
   * Configuration parameters for the OPAQUE protocol. Default is
   * OpaqueConfiguration.defaultConfiguration()
   */
  private OpaqueConfiguration opaqueConfiguration;

  /** The client PakeSessionRegistry. Default is the InMemoryPakeSessionRegistry. */
  private PakeSessionRegistry<ClientPakeRecord> clientPakeSessionRegistry;

  // Set by builder. No default values
  /** Client identifier */
  private String clientIdentity;

  /** The default session duration for all created sessions. */
  private Duration sessionDuration;

  /** Service type registry, including all supported service types. */
  private ServiceTypeRegistry serviceTypeRegistry;

  /** Service exchange connector, handling HTTP requests and responses to the RPS-Ops server. */
  private ServiceExchangeConnector serviceExchangeConnector;

  /** Security context configuration map, keyed by context identifier. */
  private Map<String, ClientContextConfiguration> contextConfigurationMap;

  /**
   * Creates a new builder instance for constructing an {@code OpaqueRpsOpsConfiguration}. The
   * builder allows for fluent configuration of the required parameters and settings to initialize
   * an {@code OpaqueRpsOpsConfiguration} instance.
   *
   * @return a new instance of {@code Builder} to configure and construct an {@code
   *     OpaqueRpsOpsConfiguration}
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * Builder class for constructing instances of {@code OpaqueRpsOpsConfiguration}. This class
   * provides methods to configure various components and parameters needed for the OPAQUE RPS-Ops
   * configuration, including cryptographic settings, session management, context configurations,
   * and registry components.
   *
   * <p>
   * Each method in this builder supports method chaining for a fluent API design, facilitating the
   * easy and clear creation of custom configurations.
   */
  public static class Builder {

    private final OpaqueR2PSConfiguration configuration;

    /**
     * Constructs a new instance of the {@code Builder} class with default configurations.
     * Initializes the internal configuration to an instance of {@code OpaqueRpsOpsConfiguration},
     * setting up its default values for Opaque configuration and an in-memory PAKE session
     * registry.
     */
    public Builder() {
      this.configuration = new OpaqueR2PSConfiguration();
      this.configuration.setOpaqueConfiguration(OpaqueConfiguration.defaultConfiguration());
      this.configuration.setClientPakeSessionRegistry(new InMemoryPakeSessionRegistry<>());
    }

    /**
     * Sets the client identity in the builder's configuration. The client identity is used to
     * uniquely identify the client interacting with the system during secure communication.
     *
     * @param clientIdentity a {@code String} representing the identity of the client involved in
     *        the operation
     * @return the instance of the {@code Builder} for method chaining
     */
    public Builder clientIdentity(String clientIdentity) {
      this.configuration.setClientIdentity(clientIdentity);
      return this;
    }

    /**
     * Sets the {@code OpaqueConfiguration} for the builder. The OpaqueConfiguration defines the
     * parameters used in the OPAQUE protocol, such as the cryptographic curve, hash functions, and
     * stretching profiles. This allows customization of the cryptographic settings for secure
     * client-server operations.
     *
     * @param opaqueConfiguration the {@code OpaqueConfiguration} to set in the builder, specifying
     *        the cryptographic and protocol settings for OPAQUE
     * @return the instance of the {@code Builder} for method chaining
     */
    public Builder opaqueConfiguration(OpaqueConfiguration opaqueConfiguration) {
      this.configuration.setOpaqueConfiguration(opaqueConfiguration);
      return this;
    }

    /**
     * Sets the session duration in the configuration. This duration specifies the length of time a
     * context session remains valid.
     *
     * @param contextSessionDuration the duration to be set for the session validity
     * @return the instance of the Builder for method chaining
     */
    public Builder contextSessionDuration(Duration contextSessionDuration) {
      this.configuration.setSessionDuration(contextSessionDuration);
      return this;
    }

    /**
     * Sets the client PAKE (Password Authenticated Key Exchange) session registry in the
     * configuration. This registry manages PAKE session records for clients, including their
     * creation, retrieval, and lifecycle management.
     *
     * @param clientPakeSessionRegistry the PAKE session registry to be set in the configuration,
     *        which handles instances of {@code ClientPakeRecord}.
     * @return the instance of the Builder for method chaining.
     */
    public Builder clientPakeSessionRegistry(
        PakeSessionRegistry<ClientPakeRecord> clientPakeSessionRegistry) {
      this.configuration.setClientPakeSessionRegistry(clientPakeSessionRegistry);
      return this;
    }

    /**
     * Sets the service type registry in the configuration. This registry provides a mapping and
     * management for various service types and their associated encryption options.
     *
     * @param serviceTypeRegistry the {@code ServiceTypeRegistry} to be set in the configuration
     * @return the instance of the {@code Builder} for method chaining
     */
    public Builder serviceTypeRegistry(ServiceTypeRegistry serviceTypeRegistry) {
      this.configuration.setServiceTypeRegistry(serviceTypeRegistry);
      return this;
    }

    /**
     * Sets the ServiceExchangeConnector in the configuration. The ServiceExchangeConnector defines
     * the mechanism for requesting and interacting with RPS-Ops servers.
     *
     * @param serviceExchangeConnector the {@code ServiceExchangeConnector} instance to be set in
     *        the configuration
     * @return the instance of the {@code Builder} for method chaining
     */
    public Builder serviceExchangeConnector(ServiceExchangeConnector serviceExchangeConnector) {
      this.configuration.setServiceExchangeConnector(serviceExchangeConnector);
      return this;
    }

    /**
     * Adds a context and its associated configuration to the builder. This method updates the
     * configuration map by associating the provided context with the given {@code
     * ContextConfiguration}.
     *
     * @param context the name of the context to be added
     * @param clientContextConfiguration the configuration associated with the specified context
     * @return the instance of the {@code Builder} for method chaining
     */
    public Builder addContext(
        String context, ClientContextConfiguration clientContextConfiguration) {
      Map<String, ClientContextConfiguration> contextInfoMap =
          Optional.ofNullable(this.configuration.getContextConfigurationMap())
              .orElseGet(HashMap::new);
      contextInfoMap.put(context, clientContextConfiguration);
      this.configuration.setContextConfigurationMap(contextInfoMap);
      return this;
    }

    /**
     * Adds a new context configuration to the builder. The context configuration is associated with
     * the provided parameters and is stored in the builder's configuration map. This method enables
     * chaining in the builder pattern.
     *
     * @param context the name of the context to be added
     * @param kid the key identifier associated with the context
     * @param keyPair the cryptographic key pair used for signing
     * @param jwsAlgorithm the JSON Web Signature (JWS) algorithm to be used for signing
     * @param serverIdentity the identity of the server associated with the context
     * @param serverPublicKey the server's public key used for verification of server responses and
     *        opaque responses
     * @return the instance of the {@code Builder} for method chaining
     * @throws JOSEException if an error occurs during the creation of signing or verification
     *         parameters
     */
    public Builder addContext(
        String context,
        String kid,
        KeyPair keyPair,
        JWSAlgorithm jwsAlgorithm,
        String serverIdentity,
        PublicKey serverPublicKey)
        throws JOSEException {
      Map<String, ClientContextConfiguration> contextInfoMap =
          Optional.ofNullable(this.configuration.getContextConfigurationMap())
              .orElseGet(HashMap::new);
      contextInfoMap.put(
          context,
          ClientContextConfiguration.builder()
              .kid(kid)
              .contextKeyPair(keyPair)
              .signingParams(
                  new JWSSigningParams(
                      new ECDSASigner((ECPrivateKey) keyPair.getPrivate()), jwsAlgorithm))
              .serverIdentity(serverIdentity)
              .serverVerifier(new ECDSAVerifier((ECPublicKey) serverPublicKey))
              .serverPublicKey((ECPublicKey) serverPublicKey)
              .build());
      this.configuration.setContextConfigurationMap(contextInfoMap);
      return this;
    }

    /**
     * Builds and returns an instance of {@code OpaqueRpsOpsConfiguration} based on the current
     * state of the builder. Validates that all mandatory configuration fields have been initialized
     * before creating the configuration object. Throws an exception if any required field is
     * missing or if the context configuration map is empty.
     *
     * @return an instance of {@code OpaqueRpsOpsConfiguration}, fully initialized with the current
     *         builder's state.
     * @throws NullPointerException if any required configuration field is missing.
     * @throws IllegalArgumentException if the context configuration map is empty.
     */
    public OpaqueR2PSConfiguration build() {
      Objects.requireNonNull(this.configuration.getClientIdentity(), "Client identity must be set");
      Objects.requireNonNull(
          this.configuration.getServiceExchangeConnector(), "ServiceExchangeConnector must be set");
      Objects.requireNonNull(
          this.configuration.getServiceTypeRegistry(), "ServiceTypeRegistry must be set");
      Objects.requireNonNull(
          this.configuration.getSessionDuration(), "Context session duration must be set");
      Objects.requireNonNull(
          this.configuration.getContextConfigurationMap(), "ContextConfigurationMap must be set");
      if (this.configuration.getContextConfigurationMap().isEmpty()) {
        throw new IllegalArgumentException(
            "ContextConfigurationMap must contain at least one context configuration");
      }
      return this.configuration;
    }
  }
}
